// cmd/agent/main.go
// KubeRTSec Agent — eBPF-based runtime security agent for Kubernetes.
// Runs as a DaemonSet on every node.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Debasish-87/kubertsec/pkg/ebpf"
	"github.com/Debasish-87/kubertsec/pkg/response"
	"github.com/Debasish-87/kubertsec/pkg/rules"
	"github.com/Debasish-87/kubertsec/pkg/store"
)

func main() {
	log.Println("════════════════════════════════════════")
	log.Println("  KubeRTSec Agent v1.0.0 Starting")
	log.Println("════════════════════════════════════════")

	// ── Response mode ─────────────────────────────────────────
	mode := response.Mode(getEnv("RESPONSE_MODE", "alert"))
	switch mode {
	case response.ModeDetect, response.ModeAlert, response.ModeEnforce:
	default:
		log.Fatalf("invalid RESPONSE_MODE=%q (must be detect|alert|enforce)", mode)
	}
	response.SetMode(mode)
	log.Printf("[main] response mode: %s", mode)

	// ── Rule watcher (hot-reload) ─────────────────────────────
	rulesPath := getEnv("RULES_PATH", "configs/rules/process_rules.yaml")
	watcher, err := rules.NewWatcher(rulesPath, 30*time.Second)
	if err != nil {
		log.Fatalf("[main] failed to load rules: %v", err)
	}
	defer watcher.Stop()
	ebpf.SetRuleWatcher(watcher)
	log.Printf("[main] loaded %d rules from %s", watcher.Engine().RuleCount(), rulesPath)

	// ── Allowlist ─────────────────────────────────────────────
	allowlistPath := getEnv("ALLOWLIST_PATH", "configs/allowlist.yaml")
	if err := response.LoadAllowlist(allowlistPath); err != nil {
		log.Printf("[main] allowlist load warning: %v", err)
	}

	// ── Alert store ───────────────────────────────────────────
	storePath := getEnv("STORE_PATH", "/var/lib/kubertsec/alerts.db")
	if err := os.MkdirAll("/var/lib/kubertsec", 0700); err != nil {
		log.Printf("[main] store dir warning: %v", err)
	}

	alertStore, err := store.New(storePath)
	if err != nil {
		log.Printf("[main] alert store warning (running without persistence): %v", err)
	} else {
		ebpf.SetAlertStore(alertStore)
		defer alertStore.Close()
		log.Printf("[main] alert store: %s", storePath)
	}

	// ── Context + signals ─────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	// ── Store maintenance (purge alerts older than 30 days) ───
	if alertStore != nil {
		go func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					n, err := alertStore.PurgeOlderThan(30 * 24 * time.Hour)
					if err != nil {
						log.Printf("[main] purge error: %v", err)
					} else if n > 0 {
						log.Printf("[main] purged %d old alerts", n)
					}
				}
			}
		}()
	}

	// ── eBPF programs ─────────────────────────────────────────
	if err := ebpf.LoadProgram(ctx); err != nil {
		log.Fatalf("[main] eBPF agent failed to start: %v", err)
	}

	log.Println("[main] KubeRTSec Agent running — waiting for events")

	sig := <-sigChan
	log.Printf("[main] received %s — shutting down", sig)
	cancel()

	// Give workers time to drain
	time.Sleep(2 * time.Second)
	log.Println("[main] KubeRTSec Agent stopped")
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
