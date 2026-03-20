// pkg/runtime/lineage.go
// Resolves full process ancestry (PPID chain) from /proc.
// Used by the detection engine to catch shell chains like:
//   nginx → bash → nc  (container escape indicator)
//   kubelet → sh → xmrig (crypto miner in system pod)
package runtime

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxTreeDepth   = 8
	cacheEntryTTL  = 30 * time.Second
	cacheMaxSize   = 4096
)

// ProcessNode is a single node in the process ancestry chain.
type ProcessNode struct {
	PID  uint32
	PPID uint32
	Comm string
}

type cacheEntry struct {
	node    ProcessNode
	created time.Time
}

// LineageCache resolves and caches process ancestry.
type LineageCache struct {
	mu      sync.RWMutex
	entries map[uint32]cacheEntry
}

// Global instance — shared across all callers.
var globalLineage = &LineageCache{
	entries: make(map[uint32]cacheEntry, 256),
}

// GetProcessTree returns the full ancestor chain for pid, oldest first.
// e.g. [systemd, containerd, runc, nginx, bash, nc]
func GetProcessTree(pid uint32) []string {
	return globalLineage.GetTree(pid)
}

// GetParentComm returns just the immediate parent process name.
func GetParentComm(pid uint32) string {
	node := globalLineage.resolve(pid)
	if node == nil || node.PPID == 0 {
		return ""
	}
	parent := globalLineage.resolve(node.PPID)
	if parent == nil {
		return ""
	}
	return parent.Comm
}

// GetTree returns the process ancestry chain for pid, oldest ancestor first.
func (c *LineageCache) GetTree(pid uint32) []string {
	visited := make(map[uint32]bool)
	var chain []ProcessNode

	current := pid
	for i := 0; i < maxTreeDepth; i++ {
		if visited[current] {
			break
		}
		visited[current] = true

		node := c.resolve(current)
		if node == nil || node.Comm == "" {
			break
		}

		chain = append(chain, *node)

		if node.PPID == 0 || node.PPID == node.PID {
			break
		}
		current = node.PPID
	}

	// reverse: oldest ancestor first
	for l, r := 0, len(chain)-1; l < r; l, r = l+1, r-1 {
		chain[l], chain[r] = chain[r], chain[l]
	}

	result := make([]string, 0, len(chain))
	for _, n := range chain {
		if n.Comm != "" {
			result = append(result, n.Comm)
		}
	}
	return result
}

// resolve returns the ProcessNode for pid, using cache or /proc.
func (c *LineageCache) resolve(pid uint32) *ProcessNode {
	c.mu.RLock()
	if e, ok := c.entries[pid]; ok {
		if time.Since(e.created) < cacheEntryTTL {
			c.mu.RUnlock()
			n := e.node
			return &n
		}
	}
	c.mu.RUnlock()

	node := readProcStatus(pid)
	if node == nil {
		return nil
	}

	c.mu.Lock()
	if len(c.entries) >= cacheMaxSize {
		c.evictOldest()
	}
	c.entries[pid] = cacheEntry{node: *node, created: time.Now()}
	c.mu.Unlock()

	return node
}

// readProcStatus reads /proc/<pid>/status and extracts Name, Pid, PPid.
func readProcStatus(pid uint32) *ProcessNode {
	path := fmt.Sprintf("/proc/%d/status", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	node := &ProcessNode{PID: pid}
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			node.Comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "PPid:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			ppid, err := strconv.ParseUint(val, 10, 32)
			if err == nil {
				node.PPID = uint32(ppid)
			}
		}
		if node.Comm != "" && node.PPID != 0 {
			break
		}
	}

	if node.Comm == "" {
		return nil
	}
	return node
}

// evictOldest removes the single oldest cache entry (called under write lock).
func (c *LineageCache) evictOldest() {
	var oldestPID uint32
	var oldestTime time.Time

	first := true
	for pid, e := range c.entries {
		if first || e.created.Before(oldestTime) {
			oldestPID = pid
			oldestTime = e.created
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestPID)
	}
}

// EvictPID removes a PID from cache (call on process exit).
func EvictPID(pid uint32) {
	globalLineage.mu.Lock()
	delete(globalLineage.entries, pid)
	globalLineage.mu.Unlock()
}

// IsSuspiciousChain checks if the process tree contains a known attack chain.
// Returns the chain description if suspicious, empty string otherwise.
func IsSuspiciousChain(tree []string) string {
	if len(tree) < 2 {
		return ""
	}

	// Normalize
	norm := make([]string, len(tree))
	for i, t := range tree {
		norm[i] = strings.ToLower(strings.TrimSpace(t))
	}

	chainStr := strings.Join(norm, " → ")

	// web server → shell (webshell / RCE)
	webProcs := []string{"nginx", "apache", "httpd", "php", "php-fpm", "python", "ruby", "node", "java", "gunicorn", "uwsgi"}
	shellProcs := []string{"bash", "sh", "dash", "zsh", "ksh", "ash"}
	for _, wp := range webProcs {
		for _, sp := range shellProcs {
			if containsSeq(norm, wp, sp) {
				return fmt.Sprintf("webshell indicator: %s", chainStr)
			}
		}
	}

	// shell → network tool (reverse shell)
	netProcs := []string{"nc", "ncat", "netcat", "socat", "curl", "wget"}
	for _, sp := range shellProcs {
		for _, np := range netProcs {
			if containsSeq(norm, sp, np) {
				return fmt.Sprintf("reverse shell indicator: %s", chainStr)
			}
		}
	}

	// any process → crypto miner
	miners := []string{"xmrig", "minerd", "kdevtmpfsi", "kworkerds", "kthreadd2"}
	for _, m := range miners {
		for _, n := range norm {
			if strings.Contains(n, m) {
				return fmt.Sprintf("crypto miner chain: %s", chainStr)
			}
		}
	}

	// kubectl inside a container (k8s abuse)
	if containsSeq(norm, "pause", "kubectl") || containsSeq(norm, "containerd", "kubectl") {
		return fmt.Sprintf("kubectl inside container: %s", chainStr)
	}

	return ""
}

// containsSeq returns true if a appears before b in the slice.
func containsSeq(slice []string, a, b string) bool {
	ai := -1
	for i, s := range slice {
		if strings.Contains(s, a) {
			ai = i
		}
		if ai >= 0 && i > ai && strings.Contains(s, b) {
			return true
		}
	}
	return false
}
