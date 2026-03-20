// pkg/ebpf/events.go
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Debasish-87/kubertsec/pkg/correlation"
	"github.com/Debasish-87/kubertsec/pkg/response"
	"github.com/Debasish-87/kubertsec/pkg/rules"
	"github.com/Debasish-87/kubertsec/pkg/runtime"
	"github.com/Debasish-87/kubertsec/pkg/store"
	"github.com/cilium/ebpf/ringbuf"
)

// ──────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────

// Event mirrors the C struct sent from the eBPF program.
// Must match execve.bpf.c exactly (size, alignment, padding).
type Event struct {
	Pid       uint32
	Tgid      uint32
	Uid       uint32
	Comm      [16]byte
	Args      [128]byte
	Daddr     uint32
	Dport     uint16
	EventType uint8
	IsIPv6    uint8
	Daddr6    [16]byte
	Pad       [4]byte
}

const (
	EventExec    = 1
	EventConnect = 2
	EventFile    = 3
	EventClone   = 4
)

// ──────────────────────────────────────────────────────────────
// Module-level state
// ──────────────────────────────────────────────────────────────

var (
	ruleWatcher *rules.Watcher
	alertStore  *store.Store

	// Processes that should never be sent through the detection pipeline
	ignoreProcesses = map[string]struct{}{
		"cat":             {},
		"sed":             {},
		"sleep":           {},
		"cpuusage.sh":     {},
		"containerd-shim": {},
		"runc":            {},
		"pause":           {},
	}

	// Processes we will never kill (runtime processes)
	runtimeProcesses = []string{
		"runc", "containerd", "containerd-shim",
		"pause", "kubelet", "dockerd", "systemd",
	}

	// Connection dedup cache
	connCache = map[string]time.Time{}
	connLock  sync.Mutex

	// Alert dedup cache
	alertCache = map[string]time.Time{}
	alertLock  sync.Mutex
)

// SetRuleWatcher injects the hot-reloading rule watcher.
func SetRuleWatcher(w *rules.Watcher) { ruleWatcher = w }

// SetAlertStore injects the persistent alert store.
func SetAlertStore(s *store.Store) { alertStore = s }

// SetRuleEngine is kept for backward compatibility.
func SetRuleEngine(rs *rules.RuleSet) {
	e, err := rules.NewEngine(rs)
	if err != nil {
		log.Printf("[ebpf] rule engine compile error: %v", err)
		return
	}
	ruleWatcher = nil
	_ = e
}

// ──────────────────────────────────────────────────────────────
// Main event reader
// ──────────────────────────────────────────────────────────────

// ReadEvents reads from the eBPF ring buffer, decodes events, and passes
// them to the EventQueue for async processing.
func ReadEvents(ctx context.Context, rd *ringbuf.Reader) {
	log.Println("[ebpf] event reader started")

	queue := NewEventQueue(8192, 8, processEvent)
	go queue.Start(ctx)
	go cacheCleanupLoop(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("[ebpf] event reader stopping")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				log.Println("[ebpf] ring buffer closed")
				return
			}
			continue
		}

		var raw Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		process := bstring(raw.Comm[:])
		if process == "" || strings.HasPrefix(process, "runc:") {
			continue
		}
		if _, skip := ignoreProcesses[process]; skip {
			continue
		}

		// Resolve container → pod → namespace (fast path with cache)
		containerID := runtime.GetContainerID(raw.Pid)
		if containerID == "" {
			continue
		}
		pod, namespace := runtime.GetPodByContainer(containerID)
		if pod == "" || namespace == "" {
			continue
		}

		// Skip system namespaces
		if isSystemNamespace(namespace) {
			continue
		}

		args := bstring(raw.Args[:])
		ip := resolveIP(raw)

		queue.Enqueue(ProcessedEvent{
			Raw:       raw,
			Process:   process,
			Args:      args,
			Pod:       pod,
			Namespace: namespace,
			Container: containerID,
			IP:        ip,
		})
	}
}

// ──────────────────────────────────────────────────────────────
// Event processor (runs in worker goroutines)
// ──────────────────────────────────────────────────────────────

func processEvent(e ProcessedEvent) {
	switch e.Raw.EventType {
	case EventExec, EventClone:
		handleExec(e)
	case EventFile:
		handleFile(e)
	case EventConnect:
		handleConnect(e)
	}
}

// handleExec processes process execution events.
func handleExec(e ProcessedEvent) {
	process := e.Process
	args := e.Args
	pod := e.Pod
	namespace := e.Namespace
	pid := e.Raw.Pid

	// Process tree for chain detection
	tree := runtime.GetProcessTree(pid)
	parent := runtime.GetParentComm(pid)

	log.Printf(
		"[exec] pid=%d uid=%d process=%s args=%s pod=%s ns=%s parent=%s",
		pid, e.Raw.Uid, process, truncate(args, 80), pod, namespace, parent,
	)

	// Temp directory execution (stage 0 — immediate alert)
	if isTmpExec(process, args) {
		fireAlert(alert{
			RuleName:    "suspicious_tmp_execution",
			Severity:    "high",
			Message:     "Execution from temporary directory",
			Process:     process,
			Args:        args,
			Pod:         pod,
			Namespace:   namespace,
			PID:         pid,
			UID:         e.Raw.Uid,
			ProcessTree: tree,
		})
	}

	// Suspicious process chain detection
	if chainMsg := runtime.IsSuspiciousChain(tree); chainMsg != "" {
		fireAlert(alert{
			RuleName:    "suspicious_process_chain",
			Severity:    "critical",
			Message:     chainMsg,
			Process:     process,
			Args:        args,
			Pod:         pod,
			Namespace:   namespace,
			PID:         pid,
			UID:         e.Raw.Uid,
			ProcessTree: tree,
		})
	}

	// Rule engine match
	matchAndRespond(matchReq{
		process: process, args: args, parent: parent,
		namespace: namespace, pod: pod,
		pid: pid, uid: e.Raw.Uid,
		tree: tree,
	})

	// Behavioral correlation
	correlation.Detect(correlation.Event{
		Process:   process,
		Args:      args,
		Pod:       pod,
		Namespace: namespace,
	})
	correlation.DetectBehavior(process, args, pod, namespace)
}

// handleFile processes file access events.
func handleFile(e ProcessedEvent) {
	file := e.Args
	process := e.Process
	pod := e.Pod
	namespace := e.Namespace
	pid := e.Raw.Pid

	log.Printf("[file] process=%s file=%s pod=%s ns=%s", process, file, pod, namespace)

	// Sensitive file patterns
	type sensitivePattern struct {
		pattern  string
		rule     string
		severity string
		message  string
	}
	patterns := []sensitivePattern{
		{"/etc/shadow", "sensitive_file_shadow", "critical", "Read of /etc/shadow"},
		{"/etc/passwd", "sensitive_file_passwd", "high", "Read of /etc/passwd"},
		{"/root/.ssh", "sensitive_file_ssh", "critical", "SSH key access"},
		{"docker.sock", "docker_socket_access", "critical", "Docker socket access"},
		{"serviceaccount/token", "k8s_token_access", "critical", "Kubernetes SA token access"},
		{"/proc/1/root", "host_filesystem_access", "critical", "Host filesystem escape via /proc/1/root"},
		{"/host/", "host_mount_access", "high", "Host-mounted path access"},
		{"/var/run/secrets", "k8s_secrets_access", "high", "Kubernetes secrets path access"},
	}

	for _, p := range patterns {
		if strings.Contains(file, p.pattern) {
			a := alert{
				RuleName:  p.rule,
				Severity:  p.severity,
				Message:   p.message + ": " + file,
				Process:   process,
				Args:      file,
				Pod:       pod,
				Namespace: namespace,
				PID:       pid,
				UID:       e.Raw.Uid,
			}
			if !suppressAlert(p.rule, namespace, pod) {
				fireAlert(a)
				if !isRuntimeProcess(process) && (p.severity == "critical") {
					response.KillProcess(pid, process)
				}
			}
			break
		}
	}
}

// handleConnect processes outbound network connection events.
func handleConnect(e ProcessedEvent) {
	process := e.Process
	pod := e.Pod
	namespace := e.Namespace
	pid := e.Raw.Pid
	port := int(e.Raw.Dport)
	ip := e.IP

	if ip == "" || port == 0 {
		return
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}

	// Filter non-routable IPs
	if parsedIP.IsLoopback() || parsedIP.IsUnspecified() ||
		parsedIP.IsMulticast() || parsedIP.IsLinkLocalUnicast() {
		return
	}

	// Private IPs: log but don't alert (unless suspicious port)
	isPrivate := parsedIP.IsPrivate()

	// Connection dedup
	connKey := process + "|" + ip + "|" + strconv.Itoa(port) + "|" + namespace
	connLock.Lock()
	if last, ok := connCache[connKey]; ok && time.Since(last) < 30*time.Second {
		connLock.Unlock()
		return
	}
	connCache[connKey] = time.Now()
	connLock.Unlock()

	log.Printf("[net] process=%s dst=%s:%d pod=%s ns=%s private=%v",
		process, ip, port, pod, namespace, isPrivate)

	// Suspicious ports (reverse shell indicators)
	suspiciousPorts := map[int]string{
		4444:  "metasploit default",
		1337:  "common C2",
		5555:  "android debug bridge",
		9001:  "tor / C2",
		7777:  "common C2",
		31337: "elite / C2",
		1234:  "common test C2",
	}

	if reason, sus := suspiciousPorts[port]; sus {
		fireAlert(alert{
			RuleName:  "suspicious_outbound_port",
			Severity:  "critical",
			Message:   "Outbound connection to suspicious port (" + reason + ")",
			Process:   process,
			Pod:       pod,
			Namespace: namespace,
			IP:        ip,
			Port:      port,
			PID:       pid,
			UID:       e.Raw.Uid,
		})
	}

	if !isPrivate {
		// Rule engine match for external connections
		engine := getEngine()
		if engine != nil {
			rule := engine.Match(rules.MatchContext{
				Process:   process,
				Args:      e.Args,
				Namespace: namespace,
			})
			if rule != nil && !suppressAlert(rule.Name, namespace, pod) {
				a := alert{
					RuleName:  rule.Name,
					Severity:  rule.Severity,
					Message:   rule.Message,
					Process:   process,
					Pod:       pod,
					Namespace: namespace,
					IP:        ip,
					Port:      port,
					PID:       pid,
					UID:       e.Raw.Uid,
				}
				fireAlert(a)
				if !isRuntimeProcess(process) && rule.Severity == "critical" {
					response.KillProcess(pid, process)
				}
			}
		}
	}

	// Feed correlation engine
	correlation.Detect(correlation.Event{
		Process:   process,
		Args:      e.Args,
		Pod:       pod,
		Namespace: namespace,
		Port:      port,
		IP:        ip,
	})
}

// ──────────────────────────────────────────────────────────────
// Match + respond
// ──────────────────────────────────────────────────────────────

type matchReq struct {
	process, args, parent string
	namespace, pod        string
	pid, uid              uint32
	tree                  []string
	ip                    string
	port                  int
}

func matchAndRespond(req matchReq) {
	engine := getEngine()
	if engine == nil {
		return
	}

	rule := engine.Match(rules.MatchContext{
		Process:       req.process,
		Args:          req.args,
		ParentProcess: req.parent,
		Namespace:     req.namespace,
	})
	if rule == nil {
		return
	}

	if suppressAlert(rule.Name, req.namespace, req.pod) {
		return
	}

	// Allowlist check
	if allowed, reason := response.IsAllowed(req.namespace, req.pod, req.process, rule.Name); allowed {
		log.Printf("[allowlist] skipped rule=%s pod=%s reason=%s", rule.Name, req.pod, reason)
		return
	}

	a := alert{
		RuleName:    rule.Name,
		Severity:    rule.Severity,
		Message:     rule.Message,
		Process:     req.process,
		Args:        req.args,
		Pod:         req.pod,
		Namespace:   req.namespace,
		IP:          req.ip,
		Port:        req.port,
		PID:         req.pid,
		UID:         req.uid,
		ProcessTree: req.tree,
	}
	fireAlert(a)

	// Kill only in enforce mode, only critical rules, only non-runtime processes
	if !isRuntimeProcess(req.process) && rule.Severity == "critical" {
		kr := response.KillProcess(req.pid, req.process)
		if kr.Success {
			a.Killed = true
		}
	}
}

// ──────────────────────────────────────────────────────────────
// Alert dispatch
// ──────────────────────────────────────────────────────────────

type alert struct {
	RuleName    string
	Severity    string
	Message     string
	Process     string
	Args        string
	Pod         string
	Namespace   string
	IP          string
	Port        int
	PID         uint32
	UID         uint32
	ProcessTree []string
	Killed      bool
}

func fireAlert(a alert) {
	log.Printf(
		"🚨 [alert] rule=%s severity=%s pod=%s ns=%s process=%s",
		a.RuleName, a.Severity, a.Pod, a.Namespace, a.Process,
	)

	e := response.Event{
		Process:     a.Process,
		Pod:         a.Pod,
		Namespace:   a.Namespace,
		Message:     a.Message,
		RuleName:    a.RuleName,
		Severity:    a.Severity,
		Args:        a.Args,
		IP:          a.IP,
		Port:        a.Port,
		PID:         a.PID,
		ProcessTree: a.ProcessTree,
		Timestamp:   time.Now().UTC(),
		Killed:      a.Killed,
	}
	response.SendEventFull(e)

	// Persist to store
	if alertStore != nil {
		sa := &store.Alert{
			RuleName:    a.RuleName,
			Severity:    store.AlertSeverity(a.Severity),
			Message:     a.Message,
			Process:     a.Process,
			Args:        a.Args,
			Pod:         a.Pod,
			Namespace:   a.Namespace,
			IP:          a.IP,
			Port:        a.Port,
			PID:         a.PID,
			UID:         a.UID,
			ProcessTree: a.ProcessTree,
			Killed:      a.Killed,
			Timestamp:   time.Now().UTC(),
		}
		if err := alertStore.SaveAlert(sa); err != nil {
			log.Printf("[store] save alert error: %v", err)
		}
	}
}

// ──────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────

func getEngine() *rules.Engine {
	if ruleWatcher != nil {
		return ruleWatcher.Engine()
	}
	return nil
}

func isSystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}

func isRuntimeProcess(process string) bool {
	for _, p := range runtimeProcesses {
		if process == p || strings.HasPrefix(process, p+":") {
			return true
		}
	}
	return false
}

func isTmpExec(process, args string) bool {
	dirs := []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
	for _, d := range dirs {
		if strings.Contains(process, d) || strings.Contains(args, d) {
			return true
		}
	}
	return false
}

func suppressAlert(ruleName, namespace, pod string) bool {
	key := ruleName + "|" + namespace + "|" + pod
	alertLock.Lock()
	defer alertLock.Unlock()
	if last, ok := alertCache[key]; ok && time.Since(last) < 30*time.Second {
		return true
	}
	alertCache[key] = time.Now()
	return false
}

func resolveIP(e Event) string {
	if e.IsIPv6 == 1 {
		ip := net.IP(e.Daddr6[:])
		return ip.String()
	}
	if e.Daddr == 0 {
		return ""
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, e.Daddr)
	return ip.String()
}

func bstring(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return strings.ToLower(strings.TrimSpace(string(b[:i])))
		}
	}
	return strings.ToLower(strings.TrimSpace(string(b)))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func cacheCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			connLock.Lock()
			for k, t := range connCache {
				if now.Sub(t) > 30*time.Second {
					delete(connCache, k)
				}
			}
			connLock.Unlock()

			alertLock.Lock()
			for k, t := range alertCache {
				if now.Sub(t) > 5*time.Minute {
					delete(alertCache, k)
				}
			}
			alertLock.Unlock()
		}
	}
}
