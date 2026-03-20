// pkg/monitoring/metrics.go
package monitoring

import (
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type MonitoringStatus struct {
	KubeRTSec struct {
		Healthy    bool   `json:"healthy"`
		Version    string `json:"version"`
		Threats    int    `json:"threats"`
		Pods       int    `json:"pods"`
		Namespaces int    `json:"namespaces"`
	} `json:"kubertsec"`
	Prometheus struct {
		Healthy bool   `json:"healthy"`
		URL     string `json:"url"`
	} `json:"prometheus"`
	Grafana     GrafanaStatus `json:"grafana"`
	LastUpdated int64         `json:"lastUpdated"`
}

type Config struct {
	PrometheusURL    string
	GrafanaURL       string   // internal URL (used by controller to call Grafana API)
	GrafanaPublicURL string   // public URL (shown in dashboard "Open Grafana" button)
	GrafanaUser      string
	GrafanaPassword  string
	GrafanaToken     string   // service account token (optional, preferred for Grafana 10+)
}

type Service struct {
	prom      *PrometheusClient
	grafana   *GrafanaClient
	publicURL string   // browser-accessible Grafana URL
	mu        sync.RWMutex
	metrics   ClusterMetrics
	grafSt    GrafanaStatus
	updated   time.Time
}

func NewService(cfg Config) *Service {
	gc := NewGrafanaClient(cfg.GrafanaURL, cfg.GrafanaUser, cfg.GrafanaPassword)

	// Token from config or env
	token := cfg.GrafanaToken
	if token == "" {
		token = os.Getenv("GRAFANA_TOKEN")
	}
	if token != "" {
		gc.SetToken(token)
		log.Printf("[monitoring] Grafana token auth enabled")
	}

	// Public URL falls back to internal URL if not set
	publicURL := cfg.GrafanaPublicURL
	if publicURL == "" {
		publicURL = cfg.GrafanaURL
	}

	s := &Service{
		prom:      NewPrometheusClient(cfg.PrometheusURL),
		grafana:   gc,
		publicURL: publicURL,
	}
	log.Printf("[monitoring] Prometheus → %s", cfg.PrometheusURL)
	log.Printf("[monitoring] Grafana    → %s (public: %s)", cfg.GrafanaURL, publicURL)
	return s
}

func (s *Service) Start() {
	s.refresh()
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for range t.C {
			s.refresh()
		}
	}()
	go func() {
		time.Sleep(5 * time.Second)
		s.EnsureDashboard()
	}()
}

func (s *Service) refresh() {
	cm := s.prom.GetClusterMetrics()
	gs := s.grafana.GetStatus()
	s.mu.Lock()
	s.metrics = cm
	s.grafSt = gs
	s.updated = time.Now()
	s.mu.Unlock()
	if cm.Healthy {
		log.Printf("[monitoring] prom ✓ pods=%d cpu=%.3f mem=%.0fMi", cm.PodCount, cm.TotalCPU, cm.TotalMemoryMi)
	}
	if gs.Healthy {
		log.Printf("[monitoring] grafana ✓ v%s dashboards=%d", gs.Version, len(gs.Dashboards))
	}
}

func (s *Service) GetClusterMetrics() ClusterMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metrics
}

func (s *Service) GetGrafanaStatus() GrafanaStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.grafSt
}

func (s *Service) GetStatus(threats, pods, namespaces int) MonitoringStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ms MonitoringStatus
	ms.KubeRTSec.Healthy = true
	ms.KubeRTSec.Version = "1.0.0"
	ms.KubeRTSec.Threats = threats
	ms.KubeRTSec.Pods = pods
	ms.KubeRTSec.Namespaces = namespaces
	ms.Prometheus.Healthy = s.metrics.Healthy
	ms.Prometheus.URL = s.metrics.URL

	// Return public URL so browser can open it directly
	gs := s.grafSt
	if s.publicURL != "" && gs.URL != s.publicURL {
		gs.URL = s.publicURL
	}
	ms.Grafana = gs
	ms.LastUpdated = s.updated.Unix()
	return ms
}

func (s *Service) ProxyQuery(w http.ResponseWriter, query string) {
	s.prom.ProxyTo(w, query)
}

func (s *Service) EnsureDashboard() {
	s.mu.RLock()
	healthy := s.grafSt.Healthy
	dashboards := s.grafSt.Dashboards
	s.mu.RUnlock()

	if !healthy {
		return
	}

	if err := s.grafana.EnsureDashboard(dashboards); err != nil {
		log.Printf("[monitoring] grafana dashboard: %v", err)
		log.Printf("[monitoring] grafana tip: set GRAFANA_TOKEN env var with Admin service account token")
		log.Printf("[monitoring] grafana tip: or create token at %s/org/serviceaccounts", s.grafana.baseURL)
	} else {
		log.Printf("[monitoring] grafana ✓ KubeRTSec dashboard ready")
		s.refresh()
	}
}