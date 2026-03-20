# KubeRTSec — Kubernetes Runtime Security

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"/>
  <img src="https://img.shields.io/badge/go-1.21+-00ADD8?logo=go" alt="Go Version"/>
  <img src="https://img.shields.io/badge/React-19-61DAFB?logo=react" alt="React 19"/>
  <img src="https://img.shields.io/badge/eBPF-powered-orange" alt="eBPF"/>
  <img src="https://img.shields.io/badge/kubernetes-compatible-326CE5?logo=kubernetes" alt="Kubernetes"/>
  <img src="https://img.shields.io/github/actions/workflow/status/Debasish-87/kubertsec/ci.yml?label=CI" alt="CI"/>
</p>

<p align="center">
  <strong>eBPF-powered runtime threat detection for Kubernetes — catching reverse shells, crypto miners, container escapes, and privilege escalation in real time.</strong>
</p>

---

## 🚀 Dashboard Preview

<img width="1917" height="940" alt="KubeRTSec Overview Dashboard" src="https://github.com/user-attachments/assets/9bfa6de7-26f7-4e68-91f7-c4e4537ee960" />


---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
  - [Option A — Docker Compose](#option-a--docker-compose-recommended)
  - [Option B — Native Development](#option-b--native-development-3-terminals)
- [Configuration](#configuration)
  - [Backend](#backend-controller--agent)
  - [Frontend](#frontend)
- [Detection Rules](#detection-rules)
  - [Rule Schema](#rule-schema)
  - [Response Modes](#response-modes)
  - [Hot Reloading Rules](#hot-reloading-rules)
- [API Reference](#api-reference)
  - [Alerts](#alerts)
  - [Rules](#rules)
  - [Other Endpoints](#other-endpoints)
  - [WebSocket Protocol](#websocket-protocol)
- [Kubernetes Deployment](#kubernetes-deployment)
  - [Building & Pushing Images](#building--pushing-images)
- [Observability: Prometheus & Grafana](#observability-prometheus--grafana)
  - [Exposed Metrics](#exposed-metrics)
- [Attack Simulation](#attack-simulation)
- [Project Structure](#project-structure)
- [Development](#development)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Code of Conduct](#code-of-conduct)
- [License](#license)

---

## Overview

**KubeRTSec** is an open-source, production-ready Kubernetes runtime security platform. It uses **eBPF kernel tracepoints** to observe every `execve` syscall across all nodes — with zero application instrumentation required.

When a process matches a detection rule (e.g., a reverse shell, a crypto miner, or a container escape attempt), KubeRTSec can:

- **Log** the event for audit trails
- **Alert** via the controller REST API and WebSocket stream
- **Enforce** by sending `SIGKILL` to the offending process before it completes

A React 19 dashboard provides real-time visibility into alerts, pod security posture, cluster metrics, and attack timelines.

---

## Architecture

<img width="759" height="526" alt="KubeRTSec Architecture Diagram" src="https://github.com/user-attachments/assets/a20cb63f-98b2-4e34-9f43-1ef6071ea184" />

```
┌─────────────────────────────────────────────────────────────────┐
│  Every Node                                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  KubeRTSec Agent (DaemonSet)                             │   │
│  │  ┌────────────────────┐   ┌──────────────────────────┐   │   │
│  │  │  eBPF (execve      │   │  Rules Engine            │   │   │
│  │  │  tracepoint)       │──▶│  (YAML hot-reload)       │   │   │
│  │  └────────────────────┘   └────────────┬─────────────┘   │   │
│  │                                        │ POST /event     │   │
│  └────────────────────────────────────────┼─────────────────┘   │
│                                           ▼                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  KubeRTSec Controller (Deployment)                        │  │
│  │  REST API · WebSocket · BoltDB store · Prometheus metrics │  │
│  └────────────────────────┬──────────────────────────────────┘  │
│                           │ nginx reverse proxy                 │
│  ┌────────────────────────▼──────────────────────────────────┐  │
│  │  KubeRTSec Dashboard (React 19 + recharts)                │  │
│  │  Overview · Live Alerts · Pod Security · Metrics          │  │
│  │  Attack Timeline · Detection Rules                        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

| Component | Role |
|-----------|------|
| **Agent** | DaemonSet on every node; attaches eBPF tracepoint to `execve`; evaluates rules; ships events |
| **Controller** | Central REST + WebSocket server; persists alerts in BoltDB; exposes Prometheus metrics |
| **Dashboard** | React 19 SPA served via nginx; no direct kernel or K8s API access |


---

## 🔍 System Components

### Agent (eBPF Runtime)

<img width="1914" height="937" alt="eBPF Agent Runtime Monitoring" src="https://github.com/user-attachments/assets/f68f3853-12c7-4556-87b4-67b9390cb595" />

### Controller

<img width="1914" height="937" alt="Controller Alert Processing System" src="https://github.com/user-attachments/assets/f8a1c6a6-a802-48bc-a20d-29ca8c4e6e5e" />

## Features

- 🔍 **Kernel-level visibility** via eBPF — no sidecar, no ptrace, no app changes
- ⚡ **Sub-millisecond detection** with in-agent rule evaluation before network round-trip
- 🔥 **Hot-reloadable YAML rules** — update detection logic without restarting agents
- 🛡️ **Three response modes** — `detect`, `alert`, `enforce` (SIGKILL)
- 🌐 **Real-time WebSocket stream** for live alert consumers
- 📊 **Prometheus metrics** with optional Grafana dashboards
- 🔐 **Multi-event correlation** for chained attack detection
- 🗂️ **Namespace-scoped rules** — include or exclude specific namespaces
- 🧪 **Built-in attack simulation** — test your rules without a real attacker

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Go | 1.21+ | Agent + controller |
| Node.js | 20 LTS | Frontend |
| Docker + Compose | v2+ | Docker Compose mode |
| Linux kernel | 5.8+ | eBPF agent (CO-RE / BTF required) |
| kubectl | 1.26+ | Kubernetes deployment |
| Root / `CAP_BPF` | — | Agent only |

> **macOS / Windows:** The eBPF agent requires Linux. The controller and dashboard run on any platform.

---

## ⚡ Real-Time Alerts

<img width="1917" height="940" alt="Real-Time Threat Detection Alerts" src="https://github.com/user-attachments/assets/8d6edde9-bfe6-4827-adbf-a1b2aef0da78" />

---

## Quick Start

### Option A — Docker Compose (recommended)

```bash
git clone https://github.com/Debasish-87/kubertsec.git
cd kubertsec

# Copy default environment variables
cp .env.example .env

# Start controller + frontend (no eBPF required on host)
make dev
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| Controller API | http://localhost:8080 |
| Prometheus | http://localhost:9090 *(optional)* |
| Grafana | http://localhost:3001 *(optional)* |

**With full observability stack:**

```bash
docker compose --profile monitoring up --build
```

---

### Option B — Native Development (3 terminals)

**Terminal 1 — Controller:**

```bash
make controller
# or manually:
cd backend
STORE_PATH=/tmp/kubertsec-dev.db \
RULES_PATH=configs/rules/process_rules.yaml \
PROMETHEUS_URL=http://localhost:9090 \
go run ./cmd/controller
```

**Terminal 2 — eBPF Agent** *(Linux only, requires root):*

```bash
make agent
# or manually:
cd backend
sudo -E RESPONSE_MODE=alert \
  KUBESHIELD_CONTROLLER=http://localhost:8080/event \
  go run ./cmd/agent
```

**Terminal 3 — Dashboard:**

```bash
make frontend
# or manually:
cd frontend
cp .env.example .env.local
npm install
npm start
# Open http://localhost:3000
```

---

## Configuration

### Backend (controller + agent)

Copy `backend/env.example` → `backend/.env` and edit as needed:

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8080` | Controller listen address |
| `STORE_PATH` | `/tmp/kubertsec-dev.db` | BoltDB alert store path |
| `RULES_PATH` | `configs/rules/process_rules.yaml` | Detection rules file |
| `ALLOWLIST_PATH` | `configs/allowlist.yaml` | Process allowlist |
| `RESPONSE_MODE` | `alert` | `detect` / `alert` / `enforce` |
| `KUBESHIELD_CONTROLLER` | `http://localhost:8080/event` | Agent → controller endpoint |
| `PROMETHEUS_URL` | `http://localhost:9090` | Prometheus scrape target |
| `GRAFANA_URL` | `http://localhost:3001` | Grafana base URL |
| `GRAFANA_USER` | `admin` | Grafana username |
| `GRAFANA_PASSWORD` | `admin123` | Grafana password (**change in production**) |
| `GRAFANA_TOKEN` | *(empty)* | Service account token (Grafana 10+, optional) |

### Frontend

Copy `frontend/.env.example` → `frontend/.env.local`:

| Variable | Default | Description |
|----------|---------|-------------|
| `REACT_APP_API_URL` | `http://localhost:8080` | Controller URL (build-time) |
| `REACT_APP_WS_URL` | `ws://localhost:8080/ws` | WebSocket URL (auto-derived if unset) |
| `REACT_APP_STATS_INTERVAL` | `30000` | Stats polling interval (ms) |
| `REACT_APP_POD_INTERVAL` | `15000` | Pod sync interval (ms) |
| `REACT_APP_MAX_ALERTS` | `500` | Max alerts held in UI memory |

> **Production tip:** In Docker/Kubernetes, leave `REACT_APP_API_URL` empty and let nginx proxy `/api/*` and `/ws` to the controller. The same image works with any backend URL — no rebuild needed.

---

## Detection Rules

Rules live in `backend/configs/rules/process_rules.yaml`.

### Rule Schema

```yaml
rules:
  - name: reverse_shell_nc          # Unique name (used as alert rule_name)
    severity: critical              # critical | high | medium | low
    mode: enforce                   # detect | alert | enforce
    process_regex: "^nc$|^ncat$"   # Regex matched against process name
    args_any:                       # Alert if ANY of these appear in args
      - "-e /bin/bash"
      - "-e /bin/sh"
    message: "Reverse shell detected (netcat)"
    tags: [reverse_shell]
    namespaces:                     # Restrict to specific namespaces (optional)
      - production
    exclude_namespaces:             # Ignore these namespaces (optional)
      - kube-system
```

**Built-in example rules cover:**
- Reverse shells (`nc`, `ncat`, `bash -i`, `python -c`)
- Crypto miners (`xmrig`, `minergate`, `ethminer`)
- Container escapes (`nsenter`, `unshare`, `chroot`)
- Privilege escalation (`sudo`, `su`, SUID binaries)

### Rules UI

<img width="1917" height="940" alt="Detection Rules Configuration UI" src="https://github.com/user-attachments/assets/1cbbfc91-6d53-4417-87cf-90b2f94b8ee6" />

### Response Modes

| Mode | Behaviour |
|------|-----------|
| `detect` | Log only — no network calls, no process kills |
| `alert` | Log + POST event to controller |
| `enforce` | Log + POST + `SIGKILL` the offending process |

> Set `RESPONSE_MODE=detect` in staging environments to validate rules before enforcing.

### Hot Reloading Rules

Rules can be reloaded without restarting agents via any of:

1. **File watcher** — agent polls `RULES_PATH` every 30 seconds
2. **API** — `POST /api/v1/rules/reload`
3. **Dashboard** — Rules page → **↺ Reload Rules** button

---

## API Reference

All endpoints are served by the controller at `:8080`.

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/alerts` | List alerts (filterable + paginated) |
| `GET` | `/api/v1/alerts/stats` | Aggregated counts by severity |
| `GET` | `/api/v1/alerts/:id` | Single alert by ID |
| `PUT` | `/api/v1/alerts/:id/ack` | Acknowledge an alert |
| `DELETE` | `/api/v1/alerts/:id` | Delete an alert |

**Query parameters for `GET /api/v1/alerts`:**

`limit`, `offset`, `severity`, `namespace`, `pod`, `rule_name`, `process`, `since` (RFC3339), `until`, `acknowledged`

**Example:**
```bash
curl "http://localhost:8080/api/v1/alerts?severity=critical&limit=20&since=2026-01-01T00:00:00Z"
```

### Rules

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/rules` | List all active rules |
| `POST` | `/api/v1/rules` | Add a rule (in-memory only, not persisted to disk) |
| `POST` | `/api/v1/rules/reload` | Hot-reload rules from disk |
| `GET` | `/api/v1/rules/:name` | Get a rule by name |
| `DELETE` | `/api/v1/rules/:name` | Queue a rule for deletion |

### Other Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/pods` | List monitored pods |
| `GET` | `/api/v1/posture` | Latest security posture report |
| `GET` | `/api/v1/status` | Controller health + stats |
| `GET` | `/api/v1/metrics/cluster` | Prometheus-backed cluster metrics |
| `GET` | `/ws` | WebSocket event stream |
| `POST` | `/event` | Agent event ingestion endpoint |
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/metrics` | Prometheus scrape target |

### WebSocket Protocol

Connect to `ws://<controller>/ws`.

**On connect** — server sends recent alert history:

```json
{ "type": "init", "data": [<Alert>, ...] }
```

**On new detection event:**

```json
{ "type": "alert", "data": <Alert> }
```

**Alert object fields:** `id`, `timestamp`, `rule_name`, `severity`, `namespace`, `pod`, `process`, `args`, `message`, `tags`, `acknowledged`

---

## Kubernetes Deployment

```bash
# 1. Edit image registry, secrets, and resource limits
vim deploy/kubernetes/kubertsec.yaml

# 2. Apply manifests
kubectl apply -f deploy/kubernetes/kubertsec.yaml

# 3. Verify rollout
kubectl rollout status deployment/kubertsec-controller -n kubertsec
kubectl rollout status deployment/kubertsec-frontend   -n kubertsec
kubectl rollout status daemonset/kubertsec-agent       -n kubertsec

# 4. Port-forward dashboard (until Ingress is configured)
kubectl port-forward svc/kubertsec-frontend -n kubertsec 3000:80
# Open http://localhost:3000
```

The manifest includes:
- `Namespace: kubertsec`
- `DaemonSet` for the agent (privileged, `hostPID: true`)
- `Deployment` for the controller (non-root UID 1000, read-only root filesystem)
- `Deployment` for the frontend (nginx, static files only)
- `NetworkPolicy` to restrict inter-component traffic
- `ServiceAccount` and `ClusterRole` for K8s pod metadata access

### Building & Pushing Images

```bash
# Build all images
make docker-build REGISTRY=your-registry.io/your-org

# Push to registry
make docker-push REGISTRY=your-registry.io/your-org

# Or pull pre-built images from GitHub Container Registry
docker pull ghcr.io/debasish-87/kubertsec-controller:latest
docker pull ghcr.io/debasish-87/kubertsec-frontend:latest
```

---

## Observability: Prometheus & Grafana

**With port-forward (local development):**

```bash
make pf-start   # Start port-forwards
# Prometheus → http://localhost:9090
# Grafana    → http://localhost:3001

make pf-stop    # Stop port-forwards
```

### Exposed Metrics

Scrape target: `GET /metrics`

| Metric | Type | Description |
|--------|------|-------------|
| `kubertsec_alerts_total` | Gauge | Total alerts, labelled by `severity` |
| `kubertsec_alerts_last_hour` | Gauge | Alerts in the last 60 minutes |
| `kubertsec_monitored_pods` | Gauge | Pods currently visible to the agent |
| `kubertsec_monitored_namespaces` | Gauge | Active namespaces |
| `kubertsec_ws_clients` | Gauge | Active WebSocket connections |
| `kubertsec_uptime_seconds` | Counter | Controller uptime in seconds |

Pre-built Grafana dashboard JSON is available under `monitoring/grafana/`.

### Grafana Dashboard

<img width="1920" height="954" alt="Grafana Security Metrics Dashboard" src="https://github.com/user-attachments/assets/191fa74c-dc2f-49cc-9cbe-0394984f24e3" />

### Metrics View

<img width="1917" height="940" alt="Cluster Metrics and Monitoring View" src="https://github.com/user-attachments/assets/c37fbf3e-67bf-485f-b390-a5a7b233c733" />

---

## Attack Simulation

Test your setup without a real attacker:

```bash
make attack-test
```

This runs `attack-test/attack-test.sh` which:

1. Spawns simulated attack processes (`curl`, `nc`, `xmrig`, `nsenter`, …) inside a test pod
2. Posts synthetic events directly to the controller
3. Triggers each built-in detection rule
4. Reports which rules fired and at what severity

> Safe to run in a dev cluster. **Do not run in production.**


## 🧨 What Happens During an Attack?

1. A malicious process starts (e.g., reverse shell via nc)
2. eBPF agent intercepts execve syscall
3. Rule engine matches the pattern instantly
4. Alert is generated and sent to controller
5. (Optional) Process is killed via SIGKILL
6. Dashboard updates in real time


### Attack Timeline

<img width="1917" height="940" alt="Attack Timeline Visualization" src="https://github.com/user-attachments/assets/9ed8cd1c-75da-485a-96ba-a1819841727f" />


### Detection Result

<img width="1041" height="910" alt="Detection Results and Alerts Output" src="https://github.com/user-attachments/assets/82e302bc-a7aa-4491-8163-cf353c3d6f1b" />


---

## Project Structure

```
kubertsec/
├── backend/
│   ├── bpf/                        # eBPF C programs (CO-RE / BTF)
│   ├── cmd/
│   │   ├── agent/                  # eBPF agent binary entrypoint
│   │   └── controller/             # REST + WebSocket server entrypoint
│   ├── pkg/
│   │   ├── correlation/            # Multi-event attack correlation
│   │   ├── ebpf/                   # eBPF loader + ring-buffer event queue
│   │   ├── monitoring/             # Prometheus + Grafana API clients
│   │   ├── posture/                # K8s security posture assessment
│   │   ├── response/               # Process kill + allowlist enforcement
│   │   ├── rules/                  # YAML rule engine + file watcher
│   │   ├── runtime/                # Container + process lineage tracking
│   │   └── store/                  # BoltDB alert persistence
│   └── configs/
│       ├── rules/process_rules.yaml
│       └── allowlist.yaml
├── frontend/
│   └── src/
│       ├── config/                 # Environment-aware configuration
│       ├── services/               # api.js · websocket.js
│       ├── store/                  # AppStore.js (useReducer)
│       ├── hooks/                  # useAPI · usePolling · useAction
│       ├── components/             # UI.jsx · Toast.jsx
│       └── pages/                  # Overview · Alerts · Pods · Metrics
│                                   # Timeline · Rules
├── deploy/
│   └── kubernetes/kubertsec.yaml   # Production K8s manifests
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/                    # Dashboard JSON + datasource config
├── attack-test/
│   └── attack-test.sh
├── docker-compose.yml              # Production stack
├── docker-compose.override.yml     # Hot-reload dev overrides
├── Makefile
├── .env.example
└── detection_rule.yml              # Example rule for CI validation
```

---

## Development

### Running Tests

```bash
make test     # Go unit tests with race detector enabled
make vet      # go vet static analysis
make fmt      # gofmt formatting check
make lint     # golangci-lint (requires local install)
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make dev` | Start controller + frontend via Docker Compose |
| `make controller` | Run controller locally |
| `make agent` | Run eBPF agent locally (Linux + root) |
| `make frontend` | Run React dev server |
| `make test` | Run all Go tests |
| `make docker-build` | Build all Docker images |
| `make docker-push` | Push images to registry |
| `make attack-test` | Run attack simulation |
| `make pf-start` | Start Prometheus/Grafana port-forwards |
| `make pf-stop` | Stop port-forwards |

### Adding a New Detection Rule

1. Edit `backend/configs/rules/process_rules.yaml`
2. Follow the [rule schema](#rule-schema)
3. Hot-reload via `POST /api/v1/rules/reload` or `make attack-test` to validate
4. Submit a PR with the rule and a test case in `attack-test/`

---

## Security Considerations

| Topic | Detail |
|-------|--------|
| **Agent privileges** | The agent requires `privileged: true` and `hostPID: true` — inherent to eBPF kernel tracing. Review the DaemonSet manifest carefully before production deployment. |
| **Controller** | Runs as non-root (UID 1000) with a read-only root filesystem. |
| **Frontend** | Serves static files only and proxies to the controller — no direct kernel or K8s API access. |
| **Grafana password** | Change `GRAFANA_PASSWORD` before any production deployment. |
| **TLS** | Enable TLS via Ingress + cert-manager in production. A sample annotation is included in the manifest. |
| **NetworkPolicy** | Included in the manifest. Ensure your CNI plugin enforces it. |
| **Secrets** | Do not commit `.env` files. Use Kubernetes Secrets or a secrets manager (Vault, AWS Secrets Manager). |
| **Allowlist** | Use `configs/allowlist.yaml` to suppress known-good processes and reduce alert noise. |

To report a security vulnerability, please see [SECURITY.md](SECURITY.md). **Do not open a public issue.**

---

## Contributing

We welcome contributions of all kinds — new detection rules, backend features, UI improvements, documentation, and bug reports.

1. Fork the repository and create a feature branch: `feat/your-feature`
2. `make test` must pass before submitting
3. Open a Pull Request against `main` — describe what rule, detection, or UI change your PR adds
4. Reference any related issues

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## Code of Conduct

This project adheres to the Contributor Covenant. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

---

## License

[MIT](LICENSE) © 2026 Debasish Mohanty and contributors
