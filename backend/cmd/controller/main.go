// cmd/controller/main.go
// KubeRTSec Controller — REST API + WebSocket server.
// Receives events from agents, serves the frontend dashboard.
//
// Endpoints:
//   GET    /api/v1/alerts              list alerts (filter + paginate)
//   GET    /api/v1/alerts/stats        aggregated counts
//   GET    /api/v1/alerts/:id          single alert
//   PUT    /api/v1/alerts/:id/ack      acknowledge
//   DELETE /api/v1/alerts/:id          delete
//   GET    /api/v1/rules               list all rules
//   POST   /api/v1/rules               add rule
//   PUT    /api/v1/rules/:name         update rule
//   DELETE /api/v1/rules/:name         delete rule
//   POST   /api/v1/rules/reload        hot-reload from disk
//   GET    /api/v1/posture             latest posture report
//   GET    /api/v1/status              controller health
//   GET    /api/v1/metrics/cluster     Prometheus query proxy
//   GET    /ws                         WebSocket event stream
//   POST   /event                      agent event ingestion
//   GET    /healthz                    liveness probe
//   GET    /metrics                    Prometheus metrics
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Debasish-87/kubertsec/pkg/monitoring"
	"github.com/Debasish-87/kubertsec/pkg/posture"
	"github.com/Debasish-87/kubertsec/pkg/rules"
	"github.com/Debasish-87/kubertsec/pkg/store"
	"github.com/gorilla/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ─────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────

type Server struct {
	store       *store.Store
	ruleWatcher *rules.Watcher
	monitoring  *monitoring.Service
	posture     *posture.Assessor
	k8s         kubernetes.Interface
	hub         *wsHub
	mu          sync.RWMutex
	startedAt   time.Time
}

func main() {
	log.Println("════════════════════════════════════════")
	log.Println("  KubeRTSec Controller v1.0.0 Starting")
	log.Println("════════════════════════════════════════")

	// ── Alert store ─────────────────────────────────────────
	storePath := env("STORE_PATH", "/var/lib/kubertsec/alerts.db")
	if err := os.MkdirAll(filepath.Dir(storePath), 0700); err != nil {
		log.Fatalf("store dir: %v", err)
	}
	alertStore, err := store.New(storePath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer alertStore.Close()

	// ── Rules ───────────────────────────────────────────────
	rulesPath := env("RULES_PATH", "configs/rules/process_rules.yaml")
	watcher, err := rules.NewWatcher(rulesPath, 30*time.Second)
	if err != nil {
		log.Fatalf("rules: %v", err)
	}
	defer watcher.Stop()

	// ── Kubernetes client ────────────────────────────────────
	k8sClient := buildK8sClient()

	// ── Monitoring service ───────────────────────────────────
	monSvc := monitoring.NewService(monitoring.Config{
		PrometheusURL:    env("PROMETHEUS_URL", "http://prometheus:9090"),
		GrafanaURL:       env("GRAFANA_URL", "http://grafana:3000"),
		GrafanaPublicURL: env("GRAFANA_PUBLIC_URL", ""),
		GrafanaUser:      env("GRAFANA_USER", "admin"),
		GrafanaPassword:  env("GRAFANA_PASSWORD", "admin"),
	})
	monSvc.Start()

	// ── Posture assessor ─────────────────────────────────────
	var assessor *posture.Assessor
	if k8sClient != nil {
		assessor = posture.New(k8sClient)
		assessor.Start(15 * time.Minute)
		defer assessor.Stop()
	}

	// ── WebSocket hub ────────────────────────────────────────
	hub := newWSHub()
	go hub.run()

	// ── Server ───────────────────────────────────────────────
	srv := &Server{
		store:       alertStore,
		ruleWatcher: watcher,
		monitoring:  monSvc,
		posture:     assessor,
		k8s:         k8sClient,
		hub:         hub,
		startedAt:   time.Now().UTC(),
	}

	// ── HTTP router ──────────────────────────────────────────
	mux := http.NewServeMux()

	// Agent ingestion endpoint
	mux.HandleFunc("/event", srv.handleEvent)

	// Health / metrics
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/metrics", srv.handlePrometheusMetrics)

	// WebSocket
	mux.HandleFunc("/ws", srv.handleWS)

	// API v1
	mux.HandleFunc("/api/v1/alerts", srv.handleAlerts)
	mux.HandleFunc("/api/v1/alerts/stats", srv.handleAlertStats)
	mux.HandleFunc("/api/v1/alerts/", srv.handleAlertByID)
	mux.HandleFunc("/api/v1/rules", srv.handleRules)
	mux.HandleFunc("/api/v1/rules/reload", srv.handleRulesReload)
	mux.HandleFunc("/api/v1/rules/", srv.handleRuleByName)
	mux.HandleFunc("/api/v1/posture", srv.handlePosture)
	mux.HandleFunc("/api/v1/status", srv.handleStatus)
	mux.HandleFunc("/api/v1/pods", srv.handlePods)
	mux.HandleFunc("/api/v1/metrics/cluster", srv.handleClusterMetrics)

	// CORS middleware
	handler := corsMiddleware(loggingMiddleware(mux))

	addr := env("LISTEN_ADDR", ":8080")
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// ── Graceful shutdown ────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		log.Printf("[controller] listening on %s", addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	// Store purge loop
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, _ := alertStore.PurgeOlderThan(30 * 24 * time.Hour)
				if n > 0 {
					log.Printf("[controller] purged %d old alerts", n)
				}
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("[controller] received %s — shutting down", sig)

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = httpSrv.Shutdown(shutCtx)
	log.Println("[controller] stopped")
}

// ─────────────────────────────────────────────────────────────
// Event ingestion (POST /event)
// ─────────────────────────────────────────────────────────────

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var event struct {
		Process     string    `json:"process"`
		Pod         string    `json:"pod"`
		Namespace   string    `json:"namespace"`
		Message     string    `json:"message"`
		RuleName    string    `json:"rule_name"`
		Severity    string    `json:"severity"`
		Args        string    `json:"args"`
		IP          string    `json:"ip"`
		Port        int       `json:"port"`
		PID         uint32    `json:"pid"`
		ProcessTree []string  `json:"process_tree"`
		Killed      bool      `json:"killed"`
		Timestamp   time.Time `json:"timestamp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	severity := store.AlertSeverity(event.Severity)
	if severity == "" {
		severity = store.SeverityMedium
	}

	alert := &store.Alert{
		RuleName:    event.RuleName,
		Severity:    severity,
		Message:     event.Message,
		Process:     event.Process,
		Args:        event.Args,
		Pod:         event.Pod,
		Namespace:   event.Namespace,
		IP:          event.IP,
		Port:        event.Port,
		PID:         event.PID,
		ProcessTree: event.ProcessTree,
		Killed:      event.Killed,
		Timestamp:   event.Timestamp,
	}
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now().UTC()
	}

	if err := s.store.SaveAlert(alert); err != nil {
		log.Printf("[controller] store alert error: %v", err)
	}

	// Broadcast to WebSocket clients
	s.hub.broadcast(alert)

	w.WriteHeader(http.StatusAccepted)
}

// ─────────────────────────────────────────────────────────────
// Alert endpoints
// ─────────────────────────────────────────────────────────────

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAlerts(w, r)
	default:
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := store.AlertFilter{
		Severity:  store.AlertSeverity(q.Get("severity")),
		Namespace: q.Get("namespace"),
		Pod:       q.Get("pod"),
		RuleName:  q.Get("rule_name"),
		Process:   q.Get("process"),
	}

	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Offset = n
		}
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Since = &t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.Until = &t
		}
	}
	if v := q.Get("acknowledged"); v != "" {
		b := v == "true"
		filter.Acknowledged = &b
	}

	page, err := s.store.ListAlerts(filter)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonOK(w, page)
}

func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	stats, err := s.store.Stats()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, stats)
}

func (s *Server) handleAlertByID(w http.ResponseWriter, r *http.Request) {
	// URL: /api/v1/alerts/<id>[/ack]
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/alerts/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		httpError(w, http.StatusBadRequest, "missing alert id")
		return
	}
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && action == "":
		a, err := s.store.GetAlert(id)
		if err != nil {
			httpError(w, http.StatusNotFound, err.Error())
			return
		}
		jsonOK(w, a)

	case r.Method == http.MethodPut && action == "ack":
		if err := s.store.AcknowledgeAlert(id); err != nil {
			httpError(w, http.StatusNotFound, err.Error())
			return
		}
		jsonOK(w, map[string]string{"status": "acknowledged"})

	case r.Method == http.MethodDelete && action == "":
		if err := s.store.DeleteAlert(id); err != nil {
			httpError(w, http.StatusNotFound, err.Error())
			return
		}
		jsonOK(w, map[string]string{"status": "deleted"})

	default:
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// ─────────────────────────────────────────────────────────────
// Rules endpoints
// ─────────────────────────────────────────────────────────────

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, s.ruleWatcher.Engine().GetRules())

	case http.MethodPost:
		var rule rules.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		// TODO: persist to rules file, then reload
		jsonOK(w, map[string]string{
			"status": "created",
			"name":   rule.Name,
			"note":   "restart or call /api/v1/rules/reload to apply",
		})

	default:
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleRulesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.ruleWatcher.ForceReload(); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{
		"status": "reloaded",
		"count":  s.ruleWatcher.Engine().RuleCount(),
	})
}

func (s *Server) handleRuleByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	name = strings.TrimSuffix(name, "/reload")
	if name == "" {
		httpError(w, http.StatusBadRequest, "missing rule name")
		return
	}

	allRules := s.ruleWatcher.Engine().GetRules()
	for _, rule := range allRules {
		if rule.Name == name {
			switch r.Method {
			case http.MethodGet:
				jsonOK(w, rule)
			case http.MethodDelete:
				jsonOK(w, map[string]string{
					"status": "queued_for_deletion",
					"note":   "edit rules YAML and call /api/v1/rules/reload",
				})
			default:
				httpError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}
	}
	httpError(w, http.StatusNotFound, fmt.Sprintf("rule %q not found", name))
}

// ─────────────────────────────────────────────────────────────
// Posture endpoint
// ─────────────────────────────────────────────────────────────

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.posture == nil {
		httpError(w, http.StatusServiceUnavailable, "posture assessor not available")
		return
	}
	report := s.posture.LatestReport()
	if report == nil {
		httpError(w, http.StatusServiceUnavailable, "assessment not yet complete")
		return
	}
	jsonOK(w, report)
}

// ─────────────────────────────────────────────────────────────
// Status endpoint
// ─────────────────────────────────────────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	stats, _ := s.store.Stats()
	pods, namespaces := s.countPodsAndNamespaces()

	status := map[string]interface{}{
		"healthy":    true,
		"version":    "1.0.0",
		"uptime_sec": int(time.Since(s.startedAt).Seconds()),
		"started_at": s.startedAt,
		"rules":      s.ruleWatcher.Engine().RuleCount(),
		"alerts":     stats,
		"pods":       pods,
		"namespaces": namespaces,
		"ws_clients": s.hub.clientCount(),
		"monitoring": s.monitoring.GetStatus(stats.Total, pods, namespaces),
	}

	jsonOK(w, status)
}

// ─────────────────────────────────────────────────────────────
// Pods endpoint (monitored workloads)
// ─────────────────────────────────────────────────────────────

func (s *Server) handlePods(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.k8s == nil {
		jsonOK(w, []interface{}{})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	ns := r.URL.Query().Get("namespace")
	pods, err := s.k8s.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type podInfo struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Status    string `json:"status"`
		Node      string `json:"node"`
		IP        string `json:"ip"`
	}

	var result []podInfo
	for _, p := range pods.Items {
		result = append(result, podInfo{
			Name:      p.Name,
			Namespace: p.Namespace,
			Status:    string(p.Status.Phase),
			Node:      p.Spec.NodeName,
			IP:        p.Status.PodIP,
		})
	}
	jsonOK(w, result)
}

// ─────────────────────────────────────────────────────────────
// Cluster metrics proxy
// ─────────────────────────────────────────────────────────────

func (s *Server) handleClusterMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	query := r.URL.Query().Get("query")
	if query == "" {
		jsonOK(w, s.monitoring.GetClusterMetrics())
		return
	}
	s.monitoring.ProxyQuery(w, query)
}

// ─────────────────────────────────────────────────────────────
// Prometheus metrics (for scraping by Prometheus)
// ─────────────────────────────────────────────────────────────

func (s *Server) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	stats, _ := s.store.Stats()
	pods, namespaces := s.countPodsAndNamespaces()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP kubertsec_alerts_total Total alerts by severity\n")
	fmt.Fprintf(w, "# TYPE kubertsec_alerts_total gauge\n")
	for sev, count := range stats.BySeverity {
		fmt.Fprintf(w, "kubertsec_alerts_total{severity=%q} %d\n", sev, count)
	}
	fmt.Fprintf(w, "# HELP kubertsec_alerts_last_hour Alerts in the last hour\n")
	fmt.Fprintf(w, "# TYPE kubertsec_alerts_last_hour gauge\n")
	fmt.Fprintf(w, "kubertsec_alerts_last_hour %d\n", stats.LastHour)
	fmt.Fprintf(w, "# HELP kubertsec_monitored_pods Pods currently monitored\n")
	fmt.Fprintf(w, "# TYPE kubertsec_monitored_pods gauge\n")
	fmt.Fprintf(w, "kubertsec_monitored_pods %d\n", pods)
	fmt.Fprintf(w, "# HELP kubertsec_monitored_namespaces Namespaces currently monitored\n")
	fmt.Fprintf(w, "# TYPE kubertsec_monitored_namespaces gauge\n")
	fmt.Fprintf(w, "kubertsec_monitored_namespaces %d\n", namespaces)
	fmt.Fprintf(w, "# HELP kubertsec_ws_clients Active WebSocket clients\n")
	fmt.Fprintf(w, "# TYPE kubertsec_ws_clients gauge\n")
	fmt.Fprintf(w, "kubertsec_ws_clients %d\n", s.hub.clientCount())
	fmt.Fprintf(w, "# HELP kubertsec_uptime_seconds Controller uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE kubertsec_uptime_seconds counter\n")
	fmt.Fprintf(w, "kubertsec_uptime_seconds %.0f\n", time.Since(s.startedAt).Seconds())
}

// ─────────────────────────────────────────────────────────────
// Health probe
// ─────────────────────────────────────────────────────────────

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// ─────────────────────────────────────────────────────────────
// WebSocket hub
// ─────────────────────────────────────────────────────────────

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
}

type wsHub struct {
	clients    map[*wsClient]struct{}
	mu         sync.RWMutex
	broadcast_ chan interface{}
}

type wsClient struct {
	conn *websocket.Conn
	send chan interface{}
}

func newWSHub() *wsHub {
	return &wsHub{
		clients:    make(map[*wsClient]struct{}),
		broadcast_: make(chan interface{}, 256),
	}
}

func (h *wsHub) run() {
	for msg := range h.broadcast_ {
		h.mu.RLock()
		for c := range h.clients {
			select {
			case c.send <- msg:
			default:
			}
		}
		h.mu.RUnlock()
	}
}

func (h *wsHub) broadcast(v interface{}) {
	select {
	case h.broadcast_ <- v:
	default:
	}
}

func (h *wsHub) clientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] upgrade error: %v", err)
		return
	}

	client := &wsClient{conn: conn, send: make(chan interface{}, 64)}

	s.hub.mu.Lock()
	s.hub.clients[client] = struct{}{}
	s.hub.mu.Unlock()

	// Send recent alerts on connect
	page, err := s.store.ListAlerts(store.AlertFilter{Limit: 20})
	if err == nil {
		_ = conn.WriteJSON(map[string]interface{}{
			"type": "init",
			"data": page.Alerts,
		})
	}

	// Write pump
	go func() {
		defer func() {
			conn.Close()
			s.hub.mu.Lock()
			delete(s.hub.clients, client)
			s.hub.mu.Unlock()
		}()

		for msg := range client.send {
			if err := conn.WriteJSON(map[string]interface{}{
				"type": "alert",
				"data": msg,
			}); err != nil {
				return
			}
		}
	}()

	// Read pump (keep alive, handle close)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	go func() {
		for range pingTicker.C {
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}

	close(client.send)
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func (s *Server) countPodsAndNamespaces() (int, int) {
	if s.k8s == nil {
		return 0, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pods, err := s.k8s.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, 0
	}

	nsSet := map[string]struct{}{}
	for _, p := range pods.Items {
		nsSet[p.Namespace] = struct{}{}
	}
	return len(pods.Items), len(nsSet)
}

func buildK8sClient() kubernetes.Interface {
	// Try in-cluster first
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig
		kc := env("KUBECONFIG", "")
		if kc == "" {
			if home, err := os.UserHomeDir(); err == nil {
				kc = home + "/.kube/config"
			}
		}
		config, err = clientcmd.BuildConfigFromFlags("", kc)
		if err != nil {
			log.Printf("[controller] kubernetes client unavailable: %v", err)
			return nil
		}
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("[controller] kubernetes client error: %v", err)
		return nil
	}
	log.Println("[controller] kubernetes client connected")
	return client
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip logging for high-frequency endpoints
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[http] %s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
