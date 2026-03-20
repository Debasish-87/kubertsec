// pkg/response/allowlist.go
// Per-namespace, per-pod, and per-process allowlisting.
// Allowlisted events are logged but never killed and never sent as alerts.
//
// YAML format (configs/allowlist.yaml):
//
//   entries:
//     - namespace: monitoring
//       process: prometheus
//       reason: "prometheus scrapes are expected"
//
//     - namespace: kube-system
//       reason: "all kube-system traffic trusted"
//
//     - pod: my-debug-pod
//       namespace: default
//       reason: "temporary debug pod"
//
//     - process: node_exporter
//       reason: "always trusted across namespaces"
package response

import (
	"log"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// AllowEntry defines a single allowlist rule.
// All set fields must match (AND logic).
// Unset fields are wildcards.
type AllowEntry struct {
	Namespace string `yaml:"namespace,omitempty"`
	Pod       string `yaml:"pod,omitempty"`       // prefix or exact match
	Process   string `yaml:"process,omitempty"`   // exact match
	RuleName  string `yaml:"rule_name,omitempty"` // specific rule name to suppress
	Reason    string `yaml:"reason,omitempty"`
}

type allowlistFile struct {
	Entries []AllowEntry `yaml:"entries"`
}

// Allowlist is a thread-safe allowlist that can be hot-reloaded.
type Allowlist struct {
	mu      sync.RWMutex
	entries []AllowEntry
}

// Global default allowlist instance.
var globalAllowlist = &Allowlist{}

// LoadAllowlist replaces the global allowlist from a YAML file.
func LoadAllowlist(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[allowlist] %s not found, all traffic subject to detection", path)
			return nil
		}
		return err
	}

	var af allowlistFile
	if err := yaml.Unmarshal(data, &af); err != nil {
		return err
	}

	globalAllowlist.mu.Lock()
	globalAllowlist.entries = af.Entries
	globalAllowlist.mu.Unlock()

	log.Printf("[allowlist] loaded %d entries from %s", len(af.Entries), path)
	return nil
}

// IsAllowed returns true + reason if the given event is allowlisted.
func IsAllowed(namespace, pod, process, ruleName string) (bool, string) {
	return globalAllowlist.IsAllowed(namespace, pod, process, ruleName)
}

// IsAllowed checks whether the given combination is allowlisted.
func (al *Allowlist) IsAllowed(namespace, pod, process, ruleName string) (bool, string) {
	ns := strings.ToLower(strings.TrimSpace(namespace))
	p := strings.ToLower(strings.TrimSpace(pod))
	proc := strings.ToLower(strings.TrimSpace(process))
	rn := strings.ToLower(strings.TrimSpace(ruleName))

	al.mu.RLock()
	defer al.mu.RUnlock()

	for _, e := range al.entries {
		if !matchAllowField(e.Namespace, ns) {
			continue
		}
		if !matchAllowField(e.Pod, p) {
			continue
		}
		if !matchAllowField(e.Process, proc) {
			continue
		}
		if !matchAllowField(e.RuleName, rn) {
			continue
		}
		reason := e.Reason
		if reason == "" {
			reason = "allowlisted"
		}
		return true, reason
	}

	return false, ""
}

// AddEntry programmatically adds an entry at runtime (not persisted to disk).
func (al *Allowlist) AddEntry(e AllowEntry) {
	al.mu.Lock()
	al.entries = append(al.entries, e)
	al.mu.Unlock()
}

// matchAllowField returns true if pattern matches value.
// Empty pattern = wildcard.
func matchAllowField(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	// prefix match for pod names (pod: "my-app" matches "my-app-6d9f7-xyz")
	return value == pattern || strings.HasPrefix(value, pattern)
}
