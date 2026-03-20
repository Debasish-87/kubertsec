// pkg/store/store.go
// Production-grade persistent alert store backed by BoltDB.
// Zero CGO dependency — pure Go embedded key-value store.
//
// go get go.etcd.io/bbolt
package store

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketAlerts = []byte("alerts")
	bucketMeta   = []byte("meta")
)

// Store is a thread-safe persistent alert store
type Store struct {
	db      *bolt.DB
	mu      sync.RWMutex
	path    string
	closed  bool
}

// New opens (or creates) the BoltDB database at path.
func New(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{
		Timeout:        2 * time.Second,
		NoFreelistSync: false,
	})
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", path, err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketAlerts); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bucketMeta); err != nil {
			return err
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: init buckets: %w", err)
	}

	log.Printf("[store] opened %s", path)
	return &Store{db: db, path: path}, nil
}

// Close cleanly shuts down the store.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.db.Close()
}

// SaveAlert persists an alert. If ID is empty, one is assigned.
func (s *Store) SaveAlert(a *Alert) error {
	if a == nil {
		return fmt.Errorf("store: nil alert")
	}
	if a.ID == "" {
		a.ID = newID()
	}
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("store: marshal: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAlerts).Put([]byte(a.ID), data)
	})
}

// GetAlert retrieves a single alert by ID.
func (s *Store) GetAlert(id string) (*Alert, error) {
	var a Alert
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketAlerts).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("alert %q not found", id)
		}
		return json.Unmarshal(v, &a)
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AcknowledgeAlert marks an alert as acknowledged.
func (s *Store) AcknowledgeAlert(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAlerts)
		v := b.Get([]byte(id))
		if v == nil {
			return fmt.Errorf("alert %q not found", id)
		}
		var a Alert
		if err := json.Unmarshal(v, &a); err != nil {
			return err
		}
		a.Acknowledged = true
		data, err := json.Marshal(&a)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), data)
	})
}

// DeleteAlert removes an alert permanently.
func (s *Store) DeleteAlert(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAlerts)
		if b.Get([]byte(id)) == nil {
			return fmt.Errorf("alert %q not found", id)
		}
		return b.Delete([]byte(id))
	})
}

// PurgeOlderThan removes alerts older than d duration. Returns count purged.
func (s *Store) PurgeOlderThan(d time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-d)
	var keys [][]byte

	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAlerts).ForEach(func(k, v []byte) error {
			var a Alert
			if err := json.Unmarshal(v, &a); err != nil {
				return nil
			}
			if a.Timestamp.Before(cutoff) {
				cp := make([]byte, len(k))
				copy(cp, k)
				keys = append(keys, cp)
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}

	if len(keys) == 0 {
		return 0, nil
	}

	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAlerts)
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return len(keys), err
}

// ListAlerts returns a paginated, filtered list of alerts (newest first).
func (s *Store) ListAlerts(f AlertFilter) (*AlertPage, error) {
	var all []*Alert

	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAlerts).ForEach(func(k, v []byte) error {
			var a Alert
			if err := json.Unmarshal(v, &a); err != nil {
				return nil
			}
			if matchesFilter(&a, f) {
				cp := a
				all = append(all, &cp)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	// sort newest first
	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.After(all[j].Timestamp)
	})

	total := len(all)

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	end := offset + limit
	if end > total {
		end = total
	}

	var page []*Alert
	if offset < total {
		page = all[offset:end]
	} else {
		page = []*Alert{}
	}

	return &AlertPage{
		Alerts: page,
		Total:  total,
		Offset: offset,
		Limit:  limit,
	}, nil
}

// Stats returns aggregate counts for dashboard widgets.
func (s *Store) Stats() (*AlertStats, error) {
	stats := &AlertStats{
		BySeverity: map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"low":      0,
		},
	}

	now := time.Now().UTC()
	oneHourAgo := now.Add(-time.Hour)
	oneDayAgo := now.Add(-24 * time.Hour)

	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAlerts).ForEach(func(k, v []byte) error {
			var a Alert
			if err := json.Unmarshal(v, &a); err != nil {
				return nil
			}
			stats.Total++
			stats.BySeverity[string(a.Severity)]++
			if a.Acknowledged {
				stats.Acknowledged++
			}
			if a.Killed {
				stats.Killed++
			}
			if a.Timestamp.After(oneHourAgo) {
				stats.LastHour++
			}
			if a.Timestamp.After(oneDayAgo) {
				stats.Last24h++
			}
			return nil
		})
	})
	return stats, err
}

// matchesFilter checks if an alert satisfies all filter criteria.
func matchesFilter(a *Alert, f AlertFilter) bool {
	if f.Severity != "" && a.Severity != f.Severity {
		return false
	}
	if f.Namespace != "" && !strings.EqualFold(a.Namespace, f.Namespace) {
		return false
	}
	if f.Pod != "" && !strings.Contains(strings.ToLower(a.Pod), strings.ToLower(f.Pod)) {
		return false
	}
	if f.RuleName != "" && !strings.Contains(strings.ToLower(a.RuleName), strings.ToLower(f.RuleName)) {
		return false
	}
	if f.Process != "" && !strings.Contains(strings.ToLower(a.Process), strings.ToLower(f.Process)) {
		return false
	}
	if f.Since != nil && a.Timestamp.Before(*f.Since) {
		return false
	}
	if f.Until != nil && a.Timestamp.After(*f.Until) {
		return false
	}
	if f.Acknowledged != nil && a.Acknowledged != *f.Acknowledged {
		return false
	}
	return true
}

// newID generates a unique, URL-safe alert ID.
func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x%x", b, time.Now().UnixNano())
}
