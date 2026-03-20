# Contributing to KubeRTSec

Thank you for your interest in contributing! KubeRTSec is open source under the MIT license and welcomes contributions of all kinds — bug fixes, new detection rules, eBPF improvements, frontend features, and documentation.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Adding a Detection Rule](#adding-a-detection-rule)
- [Adding a Behavioral Heuristic](#adding-a-behavioral-heuristic)
- [Adding a New eBPF Hook](#adding-a-new-ebpf-hook)
- [Pull Request Process](#pull-request-process)
- [PR Checklist](#pr-checklist)
- [Code Style](#code-style)
- [Good First Issues](#good-first-issues)
- [Getting Help](#getting-help)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to uphold it. Please report unacceptable behaviour to the maintainers via a private GitHub message or email listed in [SECURITY.md](SECURITY.md).

---

## Getting Started

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/<your-username>/kubertsec.git
cd kubertsec

# 2. Add the upstream remote so you can stay in sync
git remote add upstream https://github.com/Debasish-87/kubertsec.git

# 3. Create a focused feature branch
git checkout -b feat/your-feature-name
# Use: feat/, fix/, docs/, rule/, ebpf/, chore/ prefixes
```

> **Branch naming convention:** `feat/short-description`, `fix/issue-123`, `rule/crypto-miner-xmrig`, `docs/api-reference`, `ebpf/tcp-connect-hook`

---

## Development Setup

### Prerequisites

| Tool | Version | Required for |
|------|---------|--------------|
| Linux kernel | 5.8+ (BTF/CO-RE) | eBPF agent |
| Go | 1.21+ | Backend (agent + controller) |
| Node.js | 20 LTS | Frontend |
| clang + libbpf | latest | eBPF C changes only |
| Docker + Compose | v2+ | Full-stack dev |
| kind + kubectl | 1.26+ | Kubernetes testing |

> The controller and frontend run on macOS/Windows. The eBPF agent requires Linux.

### Install and Run

```bash
# Install Go dependencies
cd backend && go mod download && cd ..

# Install frontend dependencies
cd frontend && npm install && cd ..

# Start the full dev stack (Docker Compose — no eBPF required on host)
make dev

# Or run individual components in separate terminals:
make controller   # Terminal 1 — REST + WebSocket server
make agent        # Terminal 2 — eBPF agent (Linux, requires sudo)
make frontend     # Terminal 3 — React dev server at http://localhost:3000
```

### Verify your setup

```bash
make test           # Go unit tests with race detector
make vet            # go vet static analysis
make attack-test    # Run built-in attack simulation to confirm detections fire
```

---

## How to Contribute

| What | Where |
|------|-------|
| Bug report | Open a [GitHub Issue](https://github.com/Debasish-87/kubertsec/issues) |
| Feature request | Open a GitHub Issue or [Discussion](https://github.com/Debasish-87/kubertsec/discussions) |
| Detection rule | Edit `backend/configs/rules/process_rules.yaml` |
| Behavioral heuristic | Edit `backend/pkg/correlation/detector.go` |
| eBPF hook | Edit `bpf/execve.bpf.c` + `backend/pkg/ebpf/` |
| Frontend feature | Edit `frontend/src/` |
| Documentation | Edit `README.md` or files in `docs/` |

For significant changes, **open an issue first** to discuss the approach before investing time in implementation.

---

## Adding a Detection Rule

Rules live in `backend/configs/rules/process_rules.yaml`. No recompilation is needed — just edit and hot-reload:

```yaml
rules:
  - name: your_rule_name          # snake_case, must be globally unique
    severity: high                # critical | high | medium | low (see guide below)
    mode: alert                   # detect | alert | enforce
    process_regex: "^binary$"     # regex matched against process name
    args_any:                     # alert if ANY of these strings appear in argv
      - "--flag"
    message: "Human-readable description of the threat"
    tags: [category_tag]
    namespaces:                   # optional — restrict to specific namespaces
      - production
    exclude_namespaces:           # optional — ignore these namespaces
      - kube-system
```

### Severity Guide

| Severity | When to use | Default mode |
|----------|-------------|--------------|
| `critical` | Immediate threat — container escape, active reverse shell, crypto miner | `enforce` (SIGKILL) |
| `high` | Serious threat — privilege escalation, download tools (`curl \| bash`), chmod 777 | `alert` |
| `medium` | Suspicious but not immediately dangerous — `nmap`, `kubectl exec`, recon tools | `alert` |
| `low` | Informational — `netstat`, harmless enumeration | `detect` |

### Testing your rule

```bash
# Hot-reload without restarting
curl -X POST http://localhost:8080/api/v1/rules/reload

# Or use the make target
make attack-test
```

> All new rules **must** include a `message` field and at least one `tag`. Rules without a `message` will fail CI.

---

## Adding a Behavioral Heuristic

Behavioral heuristics correlate multiple events over time. Edit `backend/pkg/correlation/detector.go` and follow the existing patterns:

```go
// Example: detect obfuscated payload execution
if strings.Contains(args, "base64 -d") || strings.Contains(args, "base64 --decode") {
    alert("Possible obfuscated payload execution", e)
    return
}
```

**Performance rules — heuristics run on every event:**

- No I/O inside a heuristic function
- No blocking calls or channel sends with unbounded waits
- State caches must honour the 60-second expiry window — stale state causes false positives
- Add a unit test in `backend/pkg/correlation/` for every new heuristic

---

## Adding a New eBPF Hook

```bash
# 1. Add or modify the eBPF program in bpf/execve.bpf.c
# 2. Recompile the BPF object
cd backend/bpf
clang -O2 -target bpf \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c execve.bpf.c -o execve.bpf.o

# 3. Attach the program in pkg/ebpf/loader.go
kpNew, err = link.Kprobe("your_symbol", prog, nil)

# 4. Parse the new event type in pkg/ebpf/events.go
```

**eBPF coding requirements:**

- Use `__always_inline` for all helper functions
- Bounds-check **every** array access — the verifier will reject anything that could overflow
- Call `bpf_ringbuf_discard` on every early-exit path to avoid ring-buffer leaks
- Always provide a kprobe fallback using the unprefixed `sys_*` symbol for kernels < 5.11
- Test on both x86_64 and, if possible, arm64

---

## Pull Request Process

1. **Sync your branch** with upstream before opening the PR:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Keep commits focused** — one logical change per commit. Squash fixup commits before opening the PR.

3. **Write a clear PR description** covering:
   - What problem this solves or what it adds
   - How to test it
   - Any trade-offs or known limitations
   - Reference any related issues (`Closes #123`)

4. **Pass all CI checks** — CI runs `make test`, `make vet`, YAML lint, and `make attack-test`. Fix any failures before requesting review.

5. **Update documentation** if your change adds new commands, config variables, API endpoints, or changes existing behaviour.

6. **Wait for review** — a maintainer will review within a few business days. Address feedback in new commits; do not force-push after review has started.

---

## PR Checklist

Before marking your PR as ready for review, confirm all of the following:

- [ ] `make test` passes (Go unit tests with race detector)
- [ ] `make vet` passes with no warnings
- [ ] `make attack-test` passes — no regressions in existing detections
- [ ] New YAML rules include a `message` field and at least one `tag`
- [ ] Behavioral heuristics handle the 60-second state expiry
- [ ] `cd frontend && npm run build` completes with no errors or warnings
- [ ] `DEMO_MODE` in the frontend still works correctly
- [ ] README or relevant docs updated if behaviour or config changed
- [ ] No secrets, credentials, or internal hostnames committed

---

## Code Style

### Go

- All code must be `gofmt` formatted — run `make fmt` before committing
- Handle every error return; do not use `_` to discard errors silently
- No global mutable state outside of `pkg/correlation/` state cache
- Prefer table-driven tests in `*_test.go` files

### JavaScript / React

- Functional components only — no class components
- No inline style objects for repeated or shared elements — add to `UI.jsx` components
- `DEMO_MODE` must continue to work after your changes
- Run `npm run lint` before committing

### eBPF C

- `__always_inline` on every helper function
- Bounds-check every array access before use
- `bpf_ringbuf_discard` on every early-exit path
- One hook per logical concern — keep `execve.bpf.c` focused on process execution events

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(rules): add detection rule for xmrig crypto miner
fix(agent): handle nil pointer in event parser on kernel 5.15
docs(readme): document GRAFANA_TOKEN variable
rule(lateral-movement): detect kubectl exec into privileged pod
```

---

## Good First Issues

These are well-scoped tasks ideal for first-time contributors:

| Area | Task |
|------|------|
| **Posture** | Implement `pkg/posture/` checks — detect privileged containers, `runAsRoot`, missing seccomp profiles |
| **eBPF** | Expand `read_args()` in `execve.bpf.c` to capture more than 3 `argv` arguments |
| **Testing** | Add unit tests for `pkg/rules/engine.go` and `pkg/correlation/behavior.go` |
| **Research** | Document which attacks were missed in simulation and the root cause |
| **Networking** | Add IPv6 support via `tcp_v6_connect` kprobe |
| **Architecture** | Add arm64 eBPF support (currently x86_64 only) |
| **Rules** | Write detection rules for `kubectl cp`, `crictl exec`, and SUID binary abuse |
| **Frontend** | Add rule severity filter to the Alerts page |

Browse [open issues labelled `good first issue`](https://github.com/Debasish-87/kubertsec/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) for the current list.

---

## Getting Help

- **Questions about the codebase** → open a [GitHub Discussion](https://github.com/Debasish-87/kubertsec/discussions)
- **Bug reports** → open a [GitHub Issue](https://github.com/Debasish-87/kubertsec/issues)
- **Security vulnerabilities** → see [SECURITY.md](SECURITY.md) — do not open a public issue

We appreciate every contribution, no matter how small. Thank you for helping make Kubernetes runtime security more accessible.