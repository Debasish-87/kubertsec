// pkg/correlation/detector.go
// Stateless per-event detection engine.
// Rules here complement the YAML rule engine — these are hardcoded
// behavioral heuristics that don't require a config reload.
package correlation

import (
	"log"
	"net"
	"strings"
)

// Event carries all data needed for stateless detection.
type Event struct {
	Process   string
	Args      string
	Pod       string
	Namespace string
	Port      int
	IP        string
	UID       uint32
}

// DetectionResult describes a matched threat.
type DetectionResult struct {
	Rule     string
	Severity string
	Message  string
}

// Detect runs all stateless detection rules against e.
// Returns the first match, or nil.
func Detect(e Event) *DetectionResult {
	if e.Pod == "" || e.Namespace == "" {
		return nil
	}
	if isSystemNS(e.Namespace) {
		return nil
	}

	process := strings.ToLower(strings.TrimSpace(e.Process))
	args := strings.ToLower(strings.TrimSpace(e.Args))
	ip := net.ParseIP(e.IP)

	// ── Rule 1: External download to non-private IP ───────────
	if process == "curl" || process == "wget" || process == "aria2c" {
		if ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			result := &DetectionResult{
				Rule:     "external_download",
				Severity: "high",
				Message:  "External download from non-private IP",
			}
			alert(result, e)
			return result
		}
	}

	// ── Rule 2: Reverse shell arg patterns ────────────────────
	reverseShellPatterns := []string{
		"/dev/tcp", "/dev/udp",
		"bash -i", "bash -c", "sh -i", "sh -c",
		"0>&1", ">&/dev/null", "2>&1",
		"nohup ", "disown",
	}
	for _, p := range reverseShellPatterns {
		if strings.Contains(args, p) {
			result := &DetectionResult{
				Rule:     "reverse_shell_args",
				Severity: "critical",
				Message:  "Reverse shell argument pattern: " + p,
			}
			alert(result, e)
			return result
		}
	}

	// ── Rule 3: Reverse shell on suspicious port ──────────────
	suspiciousPorts := []int{4444, 1337, 5555, 9001, 7777, 31337, 1234, 6666}
	if process == "bash" || process == "sh" || process == "nc" || process == "ncat" {
		for _, p := range suspiciousPorts {
			if e.Port == p {
				result := &DetectionResult{
					Rule:     "reverse_shell_port",
					Severity: "critical",
					Message:  "Shell connecting to suspicious port",
				}
				alert(result, e)
				return result
			}
		}
	}

	// ── Rule 4: Known crypto miners ───────────────────────────
	miners := []string{"xmrig", "minerd", "kdevtmpfsi", "kworkerds", "kthreadd2", "cryptominer"}
	for _, m := range miners {
		if strings.Contains(process, m) || strings.Contains(args, m) {
			result := &DetectionResult{
				Rule:     "crypto_miner",
				Severity: "critical",
				Message:  "Crypto miner detected: " + process,
			}
			alert(result, e)
			return result
		}
	}

	// ── Rule 5: Interactive shell inside container ─────────────
	interactiveShells := []string{"bash", "sh", "zsh", "dash", "ash", "ksh", "fish"}
	for _, s := range interactiveShells {
		if process == s {
			result := &DetectionResult{
				Rule:     "interactive_shell",
				Severity: "high",
				Message:  "Interactive shell spawned inside container",
			}
			alert(result, e)
			return result
		}
	}

	// ── Rule 6: Privilege escalation ──────────────────────────
	if process == "sudo" || process == "su" || process == "pkexec" {
		result := &DetectionResult{
			Rule:     "privilege_escalation",
			Severity: "high",
			Message:  "Privilege escalation attempt via " + process,
		}
		alert(result, e)
		return result
	}

	// ── Rule 7: Data exfiltration tools ───────────────────────
	exfilTools := []string{"scp", "rsync", "ftp", "tftp", "sftp"}
	for _, t := range exfilTools {
		if process == t {
			result := &DetectionResult{
				Rule:     "data_exfiltration",
				Severity: "high",
				Message:  "Possible data exfiltration via " + process,
			}
			alert(result, e)
			return result
		}
	}

	// ── Rule 8: Container escape via docker socket ─────────────
	if strings.Contains(args, "docker.sock") || strings.Contains(args, "/var/run/docker") {
		result := &DetectionResult{
			Rule:     "docker_socket_abuse",
			Severity: "critical",
			Message:  "Docker socket access — container escape vector",
		}
		alert(result, e)
		return result
	}

	// ── Rule 9: Namespace escape tools ────────────────────────
	nsEscapeTools := []string{"nsenter", "unshare"}
	for _, t := range nsEscapeTools {
		if process == t || strings.Contains(args, t) {
			result := &DetectionResult{
				Rule:     "namespace_escape",
				Severity: "critical",
				Message:  "Namespace escape attempt via " + t,
			}
			alert(result, e)
			return result
		}
	}

	// ── Rule 10: Kubernetes credential access ─────────────────
	k8sCredPaths := []string{
		"serviceaccount", "kubernetes.io",
		"/.kube/config", "/var/run/secrets",
	}
	for _, p := range k8sCredPaths {
		if strings.Contains(args, p) {
			result := &DetectionResult{
				Rule:     "k8s_credential_access",
				Severity: "critical",
				Message:  "Kubernetes credential path accessed",
			}
			alert(result, e)
			return result
		}
	}

	// ── Rule 11: Host filesystem via /proc/1 ──────────────────
	if strings.Contains(args, "/proc/1/root") || strings.Contains(args, "/proc/1/fd") {
		result := &DetectionResult{
			Rule:     "proc1_host_escape",
			Severity: "critical",
			Message:  "Host filesystem access via /proc/1",
		}
		alert(result, e)
		return result
	}

	// ── Rule 12: Root UID execution ───────────────────────────
	if e.UID == 0 && (process == "bash" || process == "sh") {
		result := &DetectionResult{
			Rule:     "root_shell",
			Severity: "high",
			Message:  "Shell running as root (UID=0)",
		}
		alert(result, e)
		return result
	}

	// ── Rule 13: Kernel module loading ────────────────────────
	if process == "insmod" || process == "modprobe" || process == "rmmod" {
		result := &DetectionResult{
			Rule:     "kernel_module_load",
			Severity: "critical",
			Message:  "Kernel module operation inside container",
		}
		alert(result, e)
		return result
	}

	// ── Rule 14: Package manager abuse ────────────────────────
	pkgManagers := []string{"apt", "apt-get", "yum", "dnf", "apk", "pip", "pip3", "npm", "gem"}
	for _, pm := range pkgManagers {
		if process == pm {
			result := &DetectionResult{
				Rule:     "package_manager",
				Severity: "medium",
				Message:  "Package manager executed inside container: " + process,
			}
			alert(result, e)
			return result
		}
	}

	// ── Rule 15: Compiler inside container ────────────────────
	compilers := []string{"gcc", "g++", "cc", "make", "cmake", "go", "rustc"}
	for _, c := range compilers {
		if process == c {
			result := &DetectionResult{
				Rule:     "compiler_inside_container",
				Severity: "medium",
				Message:  "Compiler executed inside container: " + process,
			}
			alert(result, e)
			return result
		}
	}

	return nil
}

// alert logs a detection result.
func alert(r *DetectionResult, e Event) {
	log.Printf(
		"🚨 [detector] rule=%s severity=%s pod=%s ns=%s process=%s args=%s ip=%s port=%d",
		r.Rule, r.Severity,
		e.Pod, e.Namespace,
		e.Process, truncate(e.Args, 60),
		e.IP, e.Port,
	)
}

func isSystemNS(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
