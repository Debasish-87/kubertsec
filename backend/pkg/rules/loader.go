// pkg/rules/loader.go
package rules

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// LoadRules reads a YAML rule file and returns a compiled Engine.
func LoadRules(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rules: read %q: %w", path, err)
	}

	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("rules: parse %q: %w", path, err)
	}

	enabled := 0
	for _, r := range rs.Rules {
		if r.IsEnabled() {
			enabled++
		}
	}
	log.Printf("[rules] loaded %d rules (%d enabled) from %s", len(rs.Rules), enabled, path)
	return &rs, nil
}

// Watcher watches a rule file for changes and reloads the Engine automatically.
type Watcher struct {
	path    string
	engine  *Engine
	mu      sync.RWMutex
	modTime time.Time
	stop    chan struct{}
}

// NewWatcher creates a Watcher and starts watching path every interval.
func NewWatcher(path string, interval time.Duration) (*Watcher, error) {
	rs, err := LoadRules(path)
	if err != nil {
		return nil, err
	}

	engine, err := NewEngine(rs)
	if err != nil {
		return nil, err
	}

	info, _ := os.Stat(path)
	w := &Watcher{
		path:   path,
		engine: engine,
		stop:   make(chan struct{}),
	}
	if info != nil {
		w.modTime = info.ModTime()
	}

	go w.watch(interval)
	return w, nil
}

// Engine returns the current compiled engine (safe for concurrent use).
func (w *Watcher) Engine() *Engine {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.engine
}

// Stop shuts down the file watcher goroutine.
func (w *Watcher) Stop() {
	close(w.stop)
}

// ForceReload immediately reloads rules from disk, regardless of mtime.
func (w *Watcher) ForceReload() error {
	return w.reload()
}

func (w *Watcher) watch(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			info, err := os.Stat(w.path)
			if err != nil {
				continue
			}
			w.mu.RLock()
			changed := info.ModTime().After(w.modTime)
			w.mu.RUnlock()

			if changed {
				if err := w.reload(); err != nil {
					log.Printf("[rules] hot-reload failed: %v", err)
				} else {
					log.Printf("[rules] hot-reload successful (%d rules)", w.engine.RuleCount())
				}
			}
		}
	}
}

func (w *Watcher) reload() error {
	rs, err := LoadRules(w.path)
	if err != nil {
		return err
	}

	engine, err := NewEngine(rs)
	if err != nil {
		return err
	}

	info, _ := os.Stat(w.path)

	w.mu.Lock()
	w.engine = engine
	if info != nil {
		w.modTime = info.ModTime()
	}
	w.mu.Unlock()

	return nil
}
