// pkg/monitoring/prometheus.go
package monitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type PromResult struct {
	Metric map[string]string `json:"metric"`
	Value  [2]interface{}    `json:"value"`
}

type PodMetric struct {
	Pod       string  `json:"pod"`
	Namespace string  `json:"namespace"`
	CPU       float64 `json:"cpu"`
	MemoryMi  float64 `json:"memoryMi"`
	NetRxKBs  float64 `json:"netRxKBs"`
	NetTxKBs  float64 `json:"netTxKBs"`
}

type ClusterMetrics struct {
	Healthy       bool        `json:"healthy"`
	URL           string      `json:"url"`
	TotalCPU      float64     `json:"totalCPU"`
	TotalMemoryMi float64     `json:"totalMemoryMi"`
	TotalNetRxKBs float64     `json:"totalNetRxKBs"`
	TotalNetTxKBs float64     `json:"totalNetTxKBs"`
	PodCount      int         `json:"podCount"`
	Pods          []PodMetric `json:"pods"`
	Timestamp     int64       `json:"timestamp"`
}

type PrometheusClient struct {
	baseURL string
	client  *http.Client
}

func NewPrometheusClient(baseURL string) *PrometheusClient {
	return &PrometheusClient{baseURL: baseURL, client: &http.Client{Timeout: 8 * time.Second}}
}

func (p *PrometheusClient) Healthy() bool {
	resp, err := p.client.Get(p.baseURL + "/-/healthy")
	if err != nil { return false }
	resp.Body.Close()
	return resp.StatusCode == 200
}

func (p *PrometheusClient) Query(query string) []PromResult {
	reqURL := fmt.Sprintf("%s/api/v1/query?query=%s", p.baseURL, url.QueryEscape(query))
	resp, err := p.client.Get(reqURL)
	if err != nil { return nil }
	defer resp.Body.Close()
	var pr struct {
		Status string `json:"status"`
		Data   struct { Result []PromResult `json:"result"` } `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&pr)
	return pr.Data.Result
}

func (p *PrometheusClient) ProxyTo(w http.ResponseWriter, query string) {
	reqURL := fmt.Sprintf("%s/api/v1/query?query=%s", p.baseURL, url.QueryEscape(query))
	resp, err := p.client.Get(reqURL)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"error","error":%q,"data":{"result":[]}}`, err.Error())
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	buf := make([]byte, 32*1024)
	for { n, err := resp.Body.Read(buf); if n > 0 { w.Write(buf[:n]) }; if err != nil { break } }
}

func promFloat(v interface{}) float64 {
	switch val := v.(type) {
	case string:
		var f float64; fmt.Sscanf(val, "%f", &f); return f
	case float64:
		return val
	}
	return 0
}

func (p *PrometheusClient) GetClusterMetrics() ClusterMetrics {
	cm := ClusterMetrics{Healthy: p.Healthy(), URL: p.baseURL, Timestamp: time.Now().Unix()}
	if !cm.Healthy { return cm }

	cpuRes   := p.Query(`sum(rate(container_cpu_usage_seconds_total{container!="",container!="POD"}[2m])) by (pod,namespace)`)
	memRes   := p.Query(`sum(container_memory_working_set_bytes{container!="",container!="POD"}) by (pod,namespace)`)
	netRxRes := p.Query(`sum(rate(container_network_receive_bytes_total[2m])) by (pod,namespace)`)
	netTxRes := p.Query(`sum(rate(container_network_transmit_bytes_total[2m])) by (pod,namespace)`)

	type key struct{ pod, ns string }
	cpuMap   := map[key]float64{}
	memMap   := map[key]float64{}
	netRxMap := map[key]float64{}
	netTxMap := map[key]float64{}

	for _, r := range cpuRes   { cpuMap[key{r.Metric["pod"],r.Metric["namespace"]}]   = promFloat(r.Value[1]) }
	for _, r := range memRes   { memMap[key{r.Metric["pod"],r.Metric["namespace"]}]   = promFloat(r.Value[1]) / (1024*1024) }
	for _, r := range netRxRes { netRxMap[key{r.Metric["pod"],r.Metric["namespace"]}] = promFloat(r.Value[1]) / 1024 }
	for _, r := range netTxRes { netTxMap[key{r.Metric["pod"],r.Metric["namespace"]}] = promFloat(r.Value[1]) / 1024 }

	seen := map[key]bool{}
	for k := range cpuMap { seen[k] = true }
	for k := range memMap { seen[k] = true }

	for k := range seen {
		if k.pod == "" { continue }
		pm := PodMetric{Pod: k.pod, Namespace: k.ns, CPU: cpuMap[k], MemoryMi: memMap[k], NetRxKBs: netRxMap[k], NetTxKBs: netTxMap[k]}
		cm.Pods = append(cm.Pods, pm)
		cm.TotalCPU += pm.CPU; cm.TotalMemoryMi += pm.MemoryMi
		cm.TotalNetRxKBs += pm.NetRxKBs; cm.TotalNetTxKBs += pm.NetTxKBs
	}
	cm.PodCount = len(cm.Pods)
	return cm
}