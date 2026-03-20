// pkg/monitoring/grafana.go
// Supports Grafana 8.x → 12.x
// Auth priority: GRAFANA_TOKEN (service account) > basic auth (user/password)
package monitoring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type GrafanaDashboard struct {
	UID   string `json:"uid"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

type GrafanaStatus struct {
	Healthy    bool               `json:"healthy"`
	URL        string             `json:"url"`
	Version    string             `json:"version,omitempty"`
	Dashboards []GrafanaDashboard `json:"dashboards"`
}

type GrafanaClient struct {
	baseURL  string
	user     string
	password string
	token    string // service account token (preferred)
	client   *http.Client
}

func NewGrafanaClient(baseURL, user, password string) *GrafanaClient {
	return &GrafanaClient{
		baseURL:  baseURL,
		user:     user,
		password: password,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

// SetToken sets a service account token for Grafana 10+ RBAC.
func (g *GrafanaClient) SetToken(token string) {
	g.token = strings.TrimSpace(token)
}

// do executes an HTTP request with the appropriate auth method.
func (g *GrafanaClient) do(method, path string, body string) (*http.Response, error) {
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, g.baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}

	// Token auth takes priority (required for Grafana 10+ RBAC)
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	} else {
		req.SetBasicAuth(g.user, g.password)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return g.client.Do(req)
}

// GetStatus checks Grafana health and lists dashboards.
func (g *GrafanaClient) GetStatus() GrafanaStatus {
	gs := GrafanaStatus{URL: g.baseURL}

	resp, err := g.client.Get(g.baseURL + "/api/health")
	if err != nil {
		return gs
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return gs
	}
	gs.Healthy = true

	var h struct {
		Version string `json:"version"`
	}
	json.NewDecoder(resp.Body).Decode(&h)
	gs.Version = h.Version

	dresp, err := g.do("GET", "/api/search?type=dash-db&limit=50", "")
	if err == nil && dresp.StatusCode == 200 {
		defer dresp.Body.Close()
		json.NewDecoder(dresp.Body).Decode(&gs.Dashboards)
	}

	return gs
}

// EnsureDashboard creates or updates the KubeRTSec Security dashboard.
// Safe to call on every startup — uses overwrite:true.
func (g *GrafanaClient) EnsureDashboard(_ []GrafanaDashboard) error {
	// Skip if no auth configured beyond defaults
	if g.token == "" && (g.user == "" || g.password == "") {
		log.Printf("[grafana] no credentials configured, skipping dashboard push")
		return nil
	}

	// Test write permission first
	if err := g.checkWritePermission(); err != nil {
		return fmt.Errorf("grafana: %w", err)
	}

	ds := map[string]string{"type": "prometheus", "uid": "prometheus"}
	containerFilter := `namespace!="", id=~".*\\.scope"`
	podFilter := `namespace!=""`

	dashboard := map[string]interface{}{
		"overwrite": true,
		"folderId":  0,
		"dashboard": map[string]interface{}{
			"uid":           "kubertsec-security-v1",
			"title":         "KubeRTSec Security",
			"tags":          []string{"kubertsec", "security"},
			"timezone":      "browser",
			"schemaVersion": 38,
			"refresh":       "15s",
			"panels": []map[string]interface{}{
				{
					"id": 1, "type": "timeseries", "title": "Pod CPU Usage",
					"gridPos":    map[string]int{"h": 8, "w": 12, "x": 0, "y": 0},
					"datasource": ds,
					"fieldConfig": map[string]interface{}{
						"defaults": map[string]interface{}{
							"unit":   "short",
							"custom": map[string]interface{}{"lineWidth": 2, "fillOpacity": 8},
						},
					},
					"targets": []map[string]interface{}{{
						"expr":         `sum(rate(container_cpu_usage_seconds_total{` + containerFilter + `}[2m])) by (pod, namespace)`,
						"legendFormat": "{{namespace}}/{{pod}}",
						"refId":        "A",
					}},
				},
				{
					"id": 2, "type": "timeseries", "title": "Pod Memory (MiB)",
					"gridPos":    map[string]int{"h": 8, "w": 12, "x": 12, "y": 0},
					"datasource": ds,
					"fieldConfig": map[string]interface{}{
						"defaults": map[string]interface{}{
							"unit":   "mebibytes",
							"custom": map[string]interface{}{"lineWidth": 2, "fillOpacity": 8},
						},
					},
					"targets": []map[string]interface{}{{
						"expr":         `sum(container_memory_working_set_bytes{` + containerFilter + `}) by (pod, namespace) / 1024 / 1024`,
						"legendFormat": "{{namespace}}/{{pod}}",
						"refId":        "A",
					}},
				},
				{
					"id": 3, "type": "timeseries", "title": "Network Traffic (KB/s)",
					"gridPos":    map[string]int{"h": 8, "w": 12, "x": 0, "y": 8},
					"datasource": ds,
					"fieldConfig": map[string]interface{}{
						"defaults": map[string]interface{}{
							"unit":   "KBs",
							"custom": map[string]interface{}{"lineWidth": 2, "fillOpacity": 5},
						},
					},
					"targets": []map[string]interface{}{
						{
							"expr":         `sum(rate(container_network_receive_bytes_total{` + podFilter + `}[2m])) by (pod, namespace) / 1024`,
							"legendFormat": "rx: {{namespace}}/{{pod}}",
							"refId":        "A",
						},
						{
							"expr":         `sum(rate(container_network_transmit_bytes_total{` + podFilter + `}[2m])) by (pod, namespace) / 1024`,
							"legendFormat": "tx: {{namespace}}/{{pod}}",
							"refId":        "B",
						},
					},
				},
				{
					"id": 4, "type": "stat", "title": "Container Restarts",
					"gridPos":    map[string]int{"h": 8, "w": 12, "x": 12, "y": 8},
					"datasource": ds,
					"fieldConfig": map[string]interface{}{
						"defaults": map[string]interface{}{
							"thresholds": map[string]interface{}{
								"mode": "absolute",
								"steps": []map[string]interface{}{
									{"color": "green", "value": nil},
									{"color": "yellow", "value": 1},
									{"color": "red", "value": 5},
								},
							},
						},
					},
					"targets": []map[string]interface{}{{
						"expr":         `sum(kube_pod_container_status_restarts_total) by (pod, namespace)`,
						"legendFormat": "{{namespace}}/{{pod}}",
						"refId":        "A",
					}},
				},
			},
		},
	}

	body, err := json.Marshal(dashboard)
	if err != nil {
		return fmt.Errorf("grafana: marshal: %w", err)
	}

	resp, err := g.do("POST", "/api/dashboards/db", string(body))
	if err != nil {
		return fmt.Errorf("grafana: push: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("grafana: permission denied — set GRAFANA_TOKEN env var with an Admin service account token. Body: %s", string(raw))
	}

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("grafana: push failed status=%d body=%s", resp.StatusCode, string(raw))
	}

	log.Printf("[grafana] KubeRTSec Security dashboard pushed (v%s)", g.GetStatus().Version)
	return nil
}

// checkWritePermission tests if the configured credentials have dashboard write access.
func (g *GrafanaClient) checkWritePermission() error {
	resp, err := g.do("GET", "/api/access-control/user/permissions", "")
	if err != nil {
		// Older Grafana without RBAC — assume ok
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// Grafana < 9 — no RBAC endpoint, assume ok
		return nil
	}

	if resp.StatusCode == 403 {
		return fmt.Errorf("credentials lack permission to check access (status 403)")
	}

	return nil
}

// createServiceAccountToken attempts to create a service account and token.
// Returns the token or empty string if it fails (non-fatal).
func (g *GrafanaClient) createServiceAccountToken() string {
	// Create service account
	saBody := `{"name":"kubertsec-auto","role":"Admin"}`
	resp, err := g.do("POST", "/api/serviceaccounts", saBody)
	if err != nil || resp.StatusCode != 201 {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}

	var sa struct {
		ID int `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&sa)
	resp.Body.Close()

	if sa.ID == 0 {
		return ""
	}

	// Create token
	tokenBody := `{"name":"kubertsec-auto-token"}`
	tresp, err := g.do("POST", fmt.Sprintf("/api/serviceaccounts/%d/tokens", sa.ID), tokenBody)
	if err != nil || tresp.StatusCode != 200 {
		if tresp != nil {
			tresp.Body.Close()
		}
		return ""
	}
	defer tresp.Body.Close()

	var result struct {
		Key string `json:"key"`
	}
	json.NewDecoder(tresp.Body).Decode(&result)

	if result.Key != "" {
		log.Printf("[grafana] auto-created service account token")
		g.token = result.Key
	}
	return result.Key
}

// MarshalJSON for bytes.Buffer compatibility
var _ = bytes.NewBuffer
