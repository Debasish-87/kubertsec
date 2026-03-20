// pkg/posture/posture.go
// Security posture assessment for Kubernetes workloads.
// Evaluates running pods against CIS Benchmark and NSA/CISA Kubernetes
// Hardening Guidance recommendations.
package posture

import (
	"context"
	"log"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Severity levels for posture findings.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Finding is a single misconfiguration detected in a pod/container.
type Finding struct {
	Namespace string   `json:"namespace"`
	Pod       string   `json:"pod"`
	Container string   `json:"container"`
	Rule      string   `json:"rule"`
	Severity  Severity `json:"severity"`
	Message   string   `json:"message"`
	Reference string   `json:"reference,omitempty"` // e.g. "CIS 5.2.1"
}

// Report is the full posture assessment for the cluster.
type Report struct {
	GeneratedAt time.Time  `json:"generated_at"`
	Findings    []*Finding `json:"findings"`
	Score       int        `json:"score"`       // 0-100, higher is better
	TotalPods   int        `json:"total_pods"`
}

// Assessor runs periodic posture assessments.
type Assessor struct {
	client   kubernetes.Interface
	mu       sync.RWMutex
	latest   *Report
	stop     chan struct{}
}

// New creates an Assessor using the provided Kubernetes client.
func New(client kubernetes.Interface) *Assessor {
	return &Assessor{
		client: client,
		stop:   make(chan struct{}),
	}
}

// Start runs an immediate assessment then rescans every interval.
func (a *Assessor) Start(interval time.Duration) {
	a.runAssessment()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-a.stop:
				return
			case <-ticker.C:
				a.runAssessment()
			}
		}
	}()
}

// Stop shuts down the background scanner.
func (a *Assessor) Stop() { close(a.stop) }

// LatestReport returns the most recent assessment (nil if not yet run).
func (a *Assessor) LatestReport() *Report {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.latest
}

// runAssessment scans all non-system pods and evaluates findings.
func (a *Assessor) runAssessment() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pods, err := a.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("[posture] pod list error: %v", err)
		return
	}

	report := &Report{
		GeneratedAt: time.Now().UTC(),
		TotalPods:   len(pods.Items),
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		if isSystemNS(pod.Namespace) {
			continue
		}
		findings := assessPod(pod)
		report.Findings = append(report.Findings, findings...)
	}

	report.Score = computeScore(report)

	a.mu.Lock()
	a.latest = report
	a.mu.Unlock()

	log.Printf("[posture] assessment complete: %d findings in %d pods (score=%d)",
		len(report.Findings), report.TotalPods, report.Score)
}

// assessPod evaluates a single pod against all posture rules.
func assessPod(pod *corev1.Pod) []*Finding {
	var findings []*Finding

	podName := pod.Name
	ns := pod.Namespace

	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]

		// CIS 5.2.1: Minimize the admission of privileged containers
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			findings = append(findings, &Finding{
				Namespace: ns, Pod: podName, Container: c.Name,
				Rule:      "privileged_container",
				Severity:  Critical,
				Message:   "Container is running in privileged mode",
				Reference: "CIS 5.2.1",
			})
		}

		// CIS 5.2.2: Minimize containers running as root
		if c.SecurityContext == nil ||
			c.SecurityContext.RunAsNonRoot == nil ||
			!*c.SecurityContext.RunAsNonRoot {
			findings = append(findings, &Finding{
				Namespace: ns, Pod: podName, Container: c.Name,
				Rule:      "runs_as_root",
				Severity:  High,
				Message:   "Container may run as root (runAsNonRoot not set)",
				Reference: "CIS 5.2.2",
			})
		}

		// CIS 5.2.4: Read-only root filesystem
		if c.SecurityContext == nil ||
			c.SecurityContext.ReadOnlyRootFilesystem == nil ||
			!*c.SecurityContext.ReadOnlyRootFilesystem {
			findings = append(findings, &Finding{
				Namespace: ns, Pod: podName, Container: c.Name,
				Rule:      "writable_rootfs",
				Severity:  Medium,
				Message:   "Container root filesystem is writable",
				Reference: "CIS 5.2.4",
			})
		}

		// CIS 5.2.5: Drop all capabilities
		if c.SecurityContext == nil ||
			c.SecurityContext.Capabilities == nil ||
			len(c.SecurityContext.Capabilities.Drop) == 0 {
			findings = append(findings, &Finding{
				Namespace: ns, Pod: podName, Container: c.Name,
				Rule:      "capabilities_not_dropped",
				Severity:  High,
				Message:   "Container does not drop capabilities",
				Reference: "CIS 5.2.5",
			})
		}

		// NSA: No resource limits set
		if c.Resources.Limits == nil || len(c.Resources.Limits) == 0 {
			findings = append(findings, &Finding{
				Namespace: ns, Pod: podName, Container: c.Name,
				Rule:      "no_resource_limits",
				Severity:  Medium,
				Message:   "No resource limits set (CPU/memory) — DoS risk",
				Reference: "NSA K8s Hardening Guide §4",
			})
		}

		// CIS 5.4.1: No secrets in env vars
		for _, env := range c.Env {
			name := env.Name
			if containsAny(name, []string{"PASSWORD", "SECRET", "TOKEN", "KEY", "API_KEY", "PASSWD", "CREDENTIAL"}) {
				if env.ValueFrom == nil {
					// Raw value (not from Secret/ConfigMap)
					findings = append(findings, &Finding{
						Namespace: ns, Pod: podName, Container: c.Name,
						Rule:      "secret_in_env",
						Severity:  High,
						Message:   "Potential secret in environment variable: " + name,
						Reference: "CIS 5.4.1",
					})
				}
			}
		}

		// CIS 5.2.6: allowPrivilegeEscalation
		if c.SecurityContext == nil ||
			c.SecurityContext.AllowPrivilegeEscalation == nil ||
			*c.SecurityContext.AllowPrivilegeEscalation {
			findings = append(findings, &Finding{
				Namespace: ns, Pod: podName, Container: c.Name,
				Rule:      "privilege_escalation_allowed",
				Severity:  High,
				Message:   "allowPrivilegeEscalation is not set to false",
				Reference: "CIS 5.2.6",
			})
		}
	}

	// Pod-level checks

	// CIS 5.2.7: hostNetwork
	if pod.Spec.HostNetwork {
		findings = append(findings, &Finding{
			Namespace: ns, Pod: podName,
			Rule:      "host_network",
			Severity:  Critical,
			Message:   "Pod uses host network namespace",
			Reference: "CIS 5.2.7",
		})
	}

	// CIS 5.2.8: hostPID
	if pod.Spec.HostPID {
		findings = append(findings, &Finding{
			Namespace: ns, Pod: podName,
			Rule:      "host_pid",
			Severity:  Critical,
			Message:   "Pod shares host PID namespace",
			Reference: "CIS 5.2.8",
		})
	}

	// CIS 5.2.9: hostIPC
	if pod.Spec.HostIPC {
		findings = append(findings, &Finding{
			Namespace: ns, Pod: podName,
			Rule:      "host_ipc",
			Severity:  High,
			Message:   "Pod shares host IPC namespace",
			Reference: "CIS 5.2.9",
		})
	}

	// AutomountServiceAccountToken
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		findings = append(findings, &Finding{
			Namespace: ns, Pod: podName,
			Rule:      "automount_token",
			Severity:  Medium,
			Message:   "Service account token is auto-mounted (attack surface for token theft)",
			Reference: "CIS 5.1.6",
		})
	}

	return findings
}

// computeScore returns a 0-100 security score.
// Each critical finding -10, high -5, medium -2, low -1.
func computeScore(r *Report) int {
	if r.TotalPods == 0 {
		return 100
	}
	score := 100
	for _, f := range r.Findings {
		switch f.Severity {
		case Critical:
			score -= 10
		case High:
			score -= 5
		case Medium:
			score -= 2
		case Low:
			score -= 1
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func isSystemNS(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if len(s) >= len(p) {
			// simple case-insensitive contains
			sl := []rune(s)
			pl := []rune(p)
			for i := 0; i <= len(sl)-len(pl); i++ {
				match := true
				for j := range pl {
					a, b := sl[i+j], pl[j]
					if a >= 'a' && a <= 'z' {
						a -= 32
					}
					if b >= 'a' && b <= 'z' {
						b -= 32
					}
					if a != b {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
	}
	return false
}
