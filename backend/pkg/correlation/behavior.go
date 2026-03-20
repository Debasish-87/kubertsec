// pkg/correlation/behavior.go
// Multi-step behavioral attack chain detector.
// Tracks event sequences per pod across configurable time windows.
//
// Detected chains:
//   1. Download → Chmod → Execute (classic malware staging)
//   2. Download → Execute (chmod-less staging)
//   3. Network Recon → Lateral Move
//   4. Privilege Escalation → Shell
//   5. Credential Access → Network Exfil
package correlation

import (
	"log"
	"strings"
	"sync"
	"time"
)

// BehaviorWindow is how long we track events for a single pod.
const BehaviorWindow = 120 * time.Second

// PodState holds the behavioral state machine for a single pod.
type PodState struct {
	// Stage flags
	Downloaded   bool
	Chmod        bool
	Executed     bool
	NetworkRecon bool
	PrivEsc      bool
	CredAccess   bool

	// Network connection tracking (for exfil detection)
	ExternalConns []string

	// First event in this sequence
	FirstSeen time.Time

	// Last updated
	LastSeen time.Time
}

// BehaviorReport is emitted when a multi-step attack chain is completed.
type BehaviorReport struct {
	Chain     string
	Pod       string
	Namespace string
	Steps     []string
	Severity  string
}

var (
	states    = map[string]*PodState{}
	stateLock sync.Mutex

	// BehaviorAlerts is a channel where completed chain reports are sent.
	// Consumers (controller, logger) should read from this.
	BehaviorAlerts = make(chan BehaviorReport, 256)
)

// DetectBehavior updates the state machine for the given pod and
// emits a BehaviorReport when a full attack chain is detected.
func DetectBehavior(process, args, pod, namespace string) {
	if pod == "" || namespace == "" {
		return
	}

	key := namespace + "|" + pod
	process = strings.ToLower(strings.TrimSpace(process))
	args = strings.ToLower(strings.TrimSpace(args))

	stateLock.Lock()
	defer stateLock.Unlock()

	state, exists := states[key]
	if !exists {
		state = &PodState{}
		states[key] = state
	}

	// Expire stale state
	if !state.FirstSeen.IsZero() && time.Since(state.FirstSeen) > BehaviorWindow {
		log.Printf("[behavior] state expired for pod=%s", pod)
		delete(states, key)
		state = &PodState{}
		states[key] = state
	}

	now := time.Now()
	if state.FirstSeen.IsZero() {
		state.FirstSeen = now
	}
	state.LastSeen = now

	// ── Step tracking ─────────────────────────────────────────

	// Download
	if process == "curl" || process == "wget" || process == "aria2c" {
		if !state.Downloaded {
			state.Downloaded = true
			log.Printf("[behavior] step=download pod=%s process=%s", pod, process)
		}
	}

	// Chmod
	if process == "chmod" {
		if !state.Chmod {
			state.Chmod = true
			log.Printf("[behavior] step=chmod pod=%s", pod)
		}
	}

	// Privilege escalation
	if process == "sudo" || process == "su" || process == "setuid" || process == "setcap" {
		if !state.PrivEsc {
			state.PrivEsc = true
			log.Printf("[behavior] step=priv_esc pod=%s process=%s", pod, process)
		}
	}

	// Network recon
	if process == "nmap" || process == "masscan" || process == "netstat" ||
		process == "ss" || process == "nslookup" || process == "dig" {
		if !state.NetworkRecon {
			state.NetworkRecon = true
			log.Printf("[behavior] step=recon pod=%s process=%s", pod, process)
		}
	}

	// Credential access
	if strings.Contains(args, "/etc/shadow") ||
		strings.Contains(args, "/etc/passwd") ||
		strings.Contains(args, "serviceaccount/token") ||
		strings.Contains(args, "/.kube/config") ||
		strings.Contains(args, "/root/.ssh") {
		if !state.CredAccess {
			state.CredAccess = true
			log.Printf("[behavior] step=cred_access pod=%s args=%s", pod, args)
		}
	}

	// Execution (shell or direct)
	isExec := process == "bash" || process == "sh" || process == "zsh" || process == "dash" ||
		process == "ash" || process == "ksh" ||
		strings.Contains(process, "./") ||
		strings.HasPrefix(args, "./") ||
		strings.Contains(args, "/tmp/") ||
		strings.Contains(args, "/dev/shm/")

	// ── Chain detection ───────────────────────────────────────

	if isExec && !state.Executed {
		state.Executed = true

		// Chain 1: Download → Chmod → Execute (full malware staging)
		if state.Downloaded && state.Chmod {
			emit(BehaviorReport{
				Chain:     "malware_staging_full",
				Pod:       pod,
				Namespace: namespace,
				Steps:     []string{"download", "chmod", "execute"},
				Severity:  "critical",
			})
			delete(states, key)
			return
		}

		// Chain 2: Download → Execute (chmod-less — scripted malware)
		if state.Downloaded {
			emit(BehaviorReport{
				Chain:     "malware_staging_nochmod",
				Pod:       pod,
				Namespace: namespace,
				Steps:     []string{"download", "execute"},
				Severity:  "high",
			})
			delete(states, key)
			return
		}

		// Chain 4: PrivEsc → Shell
		if state.PrivEsc {
			emit(BehaviorReport{
				Chain:     "privilege_escalation_shell",
				Pod:       pod,
				Namespace: namespace,
				Steps:     []string{"priv_esc", "shell"},
				Severity:  "critical",
			})
			delete(states, key)
			return
		}
	}

	// Chain 3: Network Recon → Lateral move (network tool after recon)
	if state.NetworkRecon {
		isNetworkTool := process == "nc" || process == "ncat" || process == "socat" ||
			process == "curl" || process == "wget" || process == "ssh"
		if isNetworkTool && process != "nmap" && process != "masscan" {
			emit(BehaviorReport{
				Chain:     "recon_lateral_move",
				Pod:       pod,
				Namespace: namespace,
				Steps:     []string{"recon", "lateral_move"},
				Severity:  "high",
			})
			delete(states, key)
			return
		}
	}

	// Chain 5: Credential access → network tool (exfiltration)
	if state.CredAccess {
		isExfilTool := process == "curl" || process == "wget" ||
			process == "scp" || process == "rsync" || process == "ftp"
		if isExfilTool {
			emit(BehaviorReport{
				Chain:     "credential_exfiltration",
				Pod:       pod,
				Namespace: namespace,
				Steps:     []string{"cred_access", "exfil"},
				Severity:  "critical",
			})
			delete(states, key)
			return
		}
	}
}

// emit logs and non-blockingly sends a report to BehaviorAlerts.
func emit(r BehaviorReport) {
	log.Printf(
		"🚨 [behavior] chain=%s severity=%s pod=%s namespace=%s steps=%v",
		r.Chain, r.Severity, r.Pod, r.Namespace, r.Steps,
	)
	select {
	case BehaviorAlerts <- r:
	default:
		log.Printf("[behavior] WARNING: BehaviorAlerts channel full, report dropped")
	}
}

// CleanupExpiredStates removes stale pod states. Call periodically.
func CleanupExpiredStates() {
	stateLock.Lock()
	defer stateLock.Unlock()
	for key, state := range states {
		if time.Since(state.LastSeen) > BehaviorWindow {
			delete(states, key)
		}
	}
}
