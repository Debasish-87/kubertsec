// pkg/store/store_test.go
package store_test

import (
	"os"
	"testing"
	"time"

	"github.com/Debasish-87/kubertsec/pkg/store"
)

func newTestStore(t *testing.T) (*store.Store, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "kubertsec-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()

	s, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		s.Close()
		os.Remove(path)
	}
	return s, cleanup
}

func makeAlert(ruleName, ns, pod, process string, severity store.AlertSeverity) *store.Alert {
	return &store.Alert{
		RuleName:  ruleName,
		Namespace: ns,
		Pod:       pod,
		Process:   process,
		Severity:  severity,
		Message:   "test alert",
		Timestamp: time.Now().UTC(),
	}
}

func TestSaveAndGetAlert(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	a := makeAlert("rule_curl", "default", "my-pod", "curl", store.SeverityHigh)
	if err := s.SaveAlert(a); err != nil {
		t.Fatalf("SaveAlert: %v", err)
	}
	if a.ID == "" {
		t.Error("expected non-empty ID after save")
	}

	got, err := s.GetAlert(a.ID)
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if got.RuleName != a.RuleName {
		t.Errorf("expected RuleName=%q, got %q", a.RuleName, got.RuleName)
	}
	if got.Namespace != a.Namespace {
		t.Errorf("expected Namespace=%q, got %q", a.Namespace, got.Namespace)
	}
}

func TestListAlerts_NoFilter(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	for i := 0; i < 5; i++ {
		s.SaveAlert(makeAlert("rule", "ns", "pod", "bash", store.SeverityHigh))
	}

	page, err := s.ListAlerts(store.AlertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 {
		t.Errorf("expected 5 alerts, got %d", page.Total)
	}
}

func TestListAlerts_FilterSeverity(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	s.SaveAlert(makeAlert("r1", "ns", "pod", "bash", store.SeverityCritical))
	s.SaveAlert(makeAlert("r2", "ns", "pod", "curl", store.SeverityHigh))
	s.SaveAlert(makeAlert("r3", "ns", "pod", "wget", store.SeverityHigh))

	page, err := s.ListAlerts(store.AlertFilter{Severity: store.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 {
		t.Errorf("expected 2 high-severity alerts, got %d", page.Total)
	}
}

func TestListAlerts_FilterNamespace(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	s.SaveAlert(makeAlert("r1", "production", "pod-a", "bash", store.SeverityHigh))
	s.SaveAlert(makeAlert("r2", "staging", "pod-b", "bash", store.SeverityHigh))

	page, err := s.ListAlerts(store.AlertFilter{Namespace: "production"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Errorf("expected 1 production alert, got %d", page.Total)
	}
	if page.Alerts[0].Namespace != "production" {
		t.Errorf("expected production namespace, got %q", page.Alerts[0].Namespace)
	}
}

func TestListAlerts_Pagination(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	for i := 0; i < 10; i++ {
		s.SaveAlert(makeAlert("rule", "ns", "pod", "curl", store.SeverityMedium))
	}

	page, err := s.ListAlerts(store.AlertFilter{Limit: 3, Offset: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Alerts) != 3 {
		t.Errorf("expected 3 alerts in page, got %d", len(page.Alerts))
	}
	if page.Total != 10 {
		t.Errorf("expected total=10, got %d", page.Total)
	}

	page2, err := s.ListAlerts(store.AlertFilter{Limit: 3, Offset: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(page2.Alerts) != 3 {
		t.Errorf("expected 3 alerts in page2, got %d", len(page2.Alerts))
	}
}

func TestAcknowledgeAlert(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	a := makeAlert("rule", "ns", "pod", "bash", store.SeverityHigh)
	s.SaveAlert(a)

	if err := s.AcknowledgeAlert(a.ID); err != nil {
		t.Fatalf("AcknowledgeAlert: %v", err)
	}

	got, _ := s.GetAlert(a.ID)
	if !got.Acknowledged {
		t.Error("expected Acknowledged=true after ack")
	}
}

func TestDeleteAlert(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	a := makeAlert("rule", "ns", "pod", "bash", store.SeverityHigh)
	s.SaveAlert(a)

	if err := s.DeleteAlert(a.ID); err != nil {
		t.Fatalf("DeleteAlert: %v", err)
	}

	if _, err := s.GetAlert(a.ID); err == nil {
		t.Error("expected error after deleting alert, got nil")
	}
}

func TestStats(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	s.SaveAlert(makeAlert("r1", "ns", "pod", "bash", store.SeverityCritical))
	s.SaveAlert(makeAlert("r2", "ns", "pod", "curl", store.SeverityHigh))
	s.SaveAlert(makeAlert("r3", "ns", "pod", "wget", store.SeverityHigh))
	s.SaveAlert(makeAlert("r4", "ns", "pod", "ls", store.SeverityLow))

	stats, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 4 {
		t.Errorf("expected total=4, got %d", stats.Total)
	}
	if stats.BySeverity["critical"] != 1 {
		t.Errorf("expected critical=1, got %d", stats.BySeverity["critical"])
	}
	if stats.BySeverity["high"] != 2 {
		t.Errorf("expected high=2, got %d", stats.BySeverity["high"])
	}
	if stats.LastHour != 4 {
		t.Errorf("expected last_hour=4 (all just saved), got %d", stats.LastHour)
	}
}

func TestPurgeOlderThan(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	// One old alert
	old := makeAlert("old", "ns", "pod", "bash", store.SeverityHigh)
	old.Timestamp = time.Now().UTC().Add(-48 * time.Hour)
	s.SaveAlert(old)

	// One recent alert
	recent := makeAlert("recent", "ns", "pod", "bash", store.SeverityHigh)
	s.SaveAlert(recent)

	n, err := s.PurgeOlderThan(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 purged, got %d", n)
	}

	page, _ := s.ListAlerts(store.AlertFilter{})
	if page.Total != 1 {
		t.Errorf("expected 1 remaining after purge, got %d", page.Total)
	}
}

func TestListAlerts_FilterAcknowledged(t *testing.T) {
	s, cleanup := newTestStore(t)
	defer cleanup()

	a1 := makeAlert("r1", "ns", "pod", "bash", store.SeverityHigh)
	a2 := makeAlert("r2", "ns", "pod", "curl", store.SeverityHigh)
	s.SaveAlert(a1)
	s.SaveAlert(a2)
	s.AcknowledgeAlert(a1.ID)

	acked := true
	page, _ := s.ListAlerts(store.AlertFilter{Acknowledged: &acked})
	if page.Total != 1 {
		t.Errorf("expected 1 acknowledged alert, got %d", page.Total)
	}

	unacked := false
	page2, _ := s.ListAlerts(store.AlertFilter{Acknowledged: &unacked})
	if page2.Total != 1 {
		t.Errorf("expected 1 unacknowledged alert, got %d", page2.Total)
	}
}
