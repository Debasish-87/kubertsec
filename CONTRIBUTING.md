# Contributing to KubeRTSec

Thank you for your interest in contributing! KubeRTSec is open source under MIT and welcomes contributions of all kinds — bug fixes, new detection rules, eBPF improvements, frontend features, and documentation.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Adding a Detection Rule](#adding-a-detection-rule)
- [Adding a Behavioral Heuristic](#adding-a-behavioral-heuristic)
- [Adding a New eBPF Hook](#adding-a-new-ebpf-hook)
- [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)
- [Good First Issues](#good-first-issues)

---

## Getting Started

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/kubertsec.git
cd kubertsec
git remote add upstream https://github.com/Debasish-87/kubertsec.git
git checkout -b feature/your-feature-name
```

---

## Development Setup

```bash
# Prerequisites
# - Linux kernel 5.8+
# - Go 1.21+
# - Node.js 18+
# - clang + libbpf (only for eBPF changes)
# - kind + kubectl

# Install Go deps
cd backend && go mod download

# Install frontend deps
cd frontend && npm install

# Start the full stack
bash setup.sh
make controller   # Terminal 1
make agent        # Terminal 2 (needs sudo)
make frontend     # Terminal 3
```

---

## How to Contribute

| Type | Where |
|---|---|
| Bug report | Open a GitHub Issue |
| Feature request | Open a GitHub Issue or Discussion |
| Detection rule | Edit `configs/rules/process_rules.yaml` |
| Behavioral heuristic | Edit `pkg/correlation/detector.go` |
| eBPF hook | Edit `bpf/execve.bpf.c` + `pkg/ebpf/` |
| Frontend feature | Edit `frontend/src/` |
| Documentation | Edit `README.md` or `docs/` |

---

## Adding a Detection Rule

Edit `backend/configs/rules/process_rules.yaml` — no recompile needed, just restart the agent:

```yaml
- name: your_rule_name          # snake_case, unique
  process: suspicious_binary    # exact process name to match
  severity: high                # critical / high / medium / low
  message: Human-readable description of the threat
```

Severity guide:
- `critical` — auto-kills the process, immediate threat (container escape, crypto miner, reverse shell)
- `high` — serious threat, alert only (download tools, privilege escalation, chmod)
- `medium` — suspicious but not immediately dangerous (nmap, kubectl exec)
- `low` — informational (netstat, harmless recon)

---

## Adding a Behavioral Heuristic

Edit `backend/pkg/correlation/detector.go`. Follow the existing pattern:

```go
// Detect obfuscated payload execution
if strings.Contains(args, "base64 -d") || strings.Contains(args, "base64 --decode") {
    alert("Possible obfuscated payload execution", e)
    return
}
```

Rules run on every event. Keep them fast — no I/O, no blocking calls.

---

## Adding a New eBPF Hook

```bash
# 1. Add the program in bpf/execve.bpf.c
# 2. Recompile
cd backend/bpf
clang -O2 -target bpf \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c execve.bpf.c -o execve.bpf.o

# 3. Attach in pkg/ebpf/loader.go
kpNew, err = link.Kprobe("your_symbol", prog, nil)

# 4. Parse the new event in pkg/ebpf/events.go
```

Always provide a kprobe fallback (unprefixed `sys_*` symbol) for older kernels.

---

## Pull Request Process

1. Make sure `make attack-test` passes — no regressions in existing detections
2. New YAML rules must have a `message` field
3. Behavioral rules must handle the 60-second state expiry
4. Frontend changes must compile: `cd frontend && npm run build`
5. Update README if you add new commands, config, or features
6. Keep commits clean — one logical change per commit

**PR checklist:**
- [ ] `make attack-test` — no regressions
- [ ] New rules have a `message` field
- [ ] Behavioral rules handle state expiry (60s)
- [ ] `cd frontend && npm run build` — no warnings
- [ ] README updated if needed

---

## Code Style

**Go:**
- `gofmt` formatted
- Error handling on every return
- No global mutable state outside of `pkg/correlation/` state cache

**JavaScript/React:**
- Functional components only
- No inline `style` objects for repeated elements — use `UI.jsx` components
- `DEMO_MODE` must stay working

**eBPF C:**
- `__always_inline` for all helper functions
- Bounds check every array access
- `bpf_ringbuf_discard` on every early-exit path

---

## Good First Issues

- Fill out `pkg/posture/` — detect privileged containers, `runAsRoot`, missing seccomp profiles
- Expand `read_args()` in `execve.bpf.c` to capture more than 3 argv arguments
- Add unit tests for `pkg/rules/engine.go` and `pkg/correlation/behavior.go`
- Document which 8 of 27 attacks were missed and why
- Add IPv6 support via `tcp_v6_connect` kprobe
- Add `arm64` eBPF support (currently x86_64 only)

---

Questions? Open a [GitHub Discussion](https://github.com/Debasish-87/kubertsec/discussions) or an Issue.
