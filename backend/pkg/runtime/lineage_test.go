// pkg/runtime/lineage_test.go
package runtime_test

import (
	"testing"

	"github.com/Debasish-87/kubertsec/pkg/runtime"
)

func TestContainsSeqWebshell(t *testing.T) {
	// Simulating the chain: nginx → bash
	tree := []string{"systemd", "containerd", "nginx", "bash"}
	result := runtime.IsSuspiciousChain(tree)
	if result == "" {
		t.Error("expected webshell indicator for nginx → bash chain, got empty string")
	}
}

func TestContainsSeqReversShell(t *testing.T) {
	// bash → nc
	tree := []string{"containerd", "bash", "nc"}
	result := runtime.IsSuspiciousChain(tree)
	if result == "" {
		t.Error("expected reverse shell indicator for bash → nc chain")
	}
}

func TestContainsSeqMiner(t *testing.T) {
	tree := []string{"containerd", "sh", "xmrig"}
	result := runtime.IsSuspiciousChain(tree)
	if result == "" {
		t.Error("expected crypto miner chain detection for sh → xmrig")
	}
}

func TestNoSuspiciousChain(t *testing.T) {
	tree := []string{"systemd", "containerd", "nginx", "worker"}
	result := runtime.IsSuspiciousChain(tree)
	if result != "" {
		t.Errorf("expected no suspicious chain, got %q", result)
	}
}

func TestSingleElementChain(t *testing.T) {
	tree := []string{"bash"}
	result := runtime.IsSuspiciousChain(tree)
	if result != "" {
		t.Errorf("single element chain should never match, got %q", result)
	}
}

func TestEmptyChain(t *testing.T) {
	tree := []string{}
	result := runtime.IsSuspiciousChain(tree)
	if result != "" {
		t.Errorf("empty chain should never match, got %q", result)
	}
}
