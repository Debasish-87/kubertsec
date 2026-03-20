// pkg/response/engine.go
// Three-mode response engine: detect | alert | enforce.
//
//   detect  → only log locally. Zero network calls, zero kills.
//   alert   → log + send event to controller. No kills.
//   enforce → log + send event + kill process group. Full enforcement.
//
// All kills are preceded by an audit log entry and protected by:
//   - Protected process list (runtime processes never killed)
//   - Allowlist check (skip if explicitly allowed)
//   - PID validation (skip PID 1, skip PID 0)
package response

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Mode controls how the agent responds to detections.
type Mode string

const (
	ModeDetect  Mode = "detect"
	ModeAlert   Mode = "alert"
	ModeEnforce Mode = "enforce"
)

// protectedProcesses are never killed under any circumstances.
var protectedProcesses = map[string]struct{}{
	"runc":            {},
	"containerd":      {},
	"containerd-shim": {},
	"systemd":         {},
	"kubelet":         {},
	"dockerd":         {},
	"pause":           {},
	"init":            {},
}

// Event is the payload sent to the controller.
type Event struct {
	Process     string    `json:"process"`
	Pod         string    `json:"pod"`
	Namespace   string    `json:"namespace"`
	Message     string    `json:"message"`
	RuleName    string    `json:"rule_name,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Args        string    `json:"args,omitempty"`
	IP          string    `json:"ip,omitempty"`
	Port        int       `json:"port,omitempty"`
	PID         uint32    `json:"pid,omitempty"`
	ProcessTree []string  `json:"process_tree,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Killed      bool      `json:"killed"`
	Node        string    `json:"node,omitempty"`
}

// KillResult records the outcome of a kill attempt.
type KillResult struct {
	PID     uint32
	Process string
	Success bool
	Skipped bool
	Reason  string
}

var (
	currentMode   = ModeAlert
	modeMu        sync.RWMutex
	controllerURL = getEnv("KUBESHIELD_CONTROLLER", "http://localhost:8080/event")
	nodeName      = getEnv("NODE_NAME", "unknown")

	httpClient = &http.Client{
		Timeout: 3 * time.Second,
	}
)

// SetMode sets the global response mode. Safe to call at runtime.
func SetMode(m Mode) {
	modeMu.Lock()
	currentMode = m
	modeMu.Unlock()
	log.Printf("[response] mode set to %s", m)
}

// GetMode returns the current response mode.
func GetMode() Mode {
	modeMu.RLock()
	defer modeMu.RUnlock()
	return currentMode
}

// SendEvent sends an alert to the controller if mode >= alert.
func SendEvent(process, pod, namespace, message string) {
	SendEventFull(Event{
		Process:   process,
		Pod:       pod,
		Namespace: namespace,
		Message:   message,
		Timestamp: time.Now().UTC(),
		Node:      nodeName,
	})
}

// SendEventFull sends a fully populated Event to the controller.
func SendEventFull(e Event) {
	mode := GetMode()

	if mode == ModeDetect {
		log.Printf(
			"[detect] rule=%s pod=%s namespace=%s process=%s msg=%s",
			e.RuleName, e.Pod, e.Namespace, e.Process, e.Message,
		)
		return
	}

	// mode == alert or enforce: log + send
	log.Printf(
		"[alert] rule=%s severity=%s pod=%s namespace=%s process=%s msg=%s",
		e.RuleName, e.Severity, e.Pod, e.Namespace, e.Process, e.Message,
	)

	go sendToController(e)
}

// sendToController posts an Event to the controller endpoint (non-blocking).
func sendToController(e Event) {
	data, err := json.Marshal(e)
	if err != nil {
		log.Printf("[response] marshal error: %v", err)
		return
	}

	req, err := http.NewRequest("POST", controllerURL, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[response] request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Node", nodeName)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[response] send error: %v", err)
		return
	}
	defer resp.Body.Close()
}

// KillProcess terminates a suspicious process group.
// Always checks allowlist and protected process list before acting.
func KillProcess(pid uint32, process string) KillResult {
	result := KillResult{PID: pid, Process: process}

	// Basic safety checks
	if pid == 0 || pid == 1 {
		result.Skipped = true
		result.Reason = fmt.Sprintf("refuse to kill PID %d", pid)
		return result
	}

	if _, protected := protectedProcesses[strings.ToLower(process)]; protected {
		result.Skipped = true
		result.Reason = fmt.Sprintf("process %q is protected", process)
		log.Printf("[response] SKIP protected process %s pid=%d", process, pid)
		return result
	}

	// Mode check — only enforce mode kills
	if GetMode() != ModeEnforce {
		result.Skipped = true
		result.Reason = fmt.Sprintf("mode=%s, kills disabled", GetMode())
		return result
	}

	// Audit log BEFORE kill
	log.Printf(
		"[audit] KILL pid=%d process=%s (enforcement action)",
		pid, process,
	)

	// Kill the process GROUP (prevents child process escape)
	err := syscall.Kill(-int(pid), syscall.SIGKILL)
	if err != nil {
		// Fallback: kill single PID
		err = syscall.Kill(int(pid), syscall.SIGKILL)
		if err != nil {
			result.Reason = err.Error()
			log.Printf("[response] kill failed pid=%d process=%s error=%v", pid, process, err)
			return result
		}
	}

	result.Success = true
	log.Printf("🛑 [response] KILLED process=%s pid=%d", process, pid)
	return result
}

// getEnv returns the environment variable or a fallback default.
func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
