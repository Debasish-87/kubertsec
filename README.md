# KubeRTSec — Kubernetes Runtime Security

> **eBPF-powered runtime threat detection for Kubernetes.**  
> Catches reverse shells, crypto miners, container escapes, and privilege escalation — in real time.

![dashboard](https://img.shields.io/badge/dashboard-React%2019-61dafb?style=flat-square&logo=react)
![backend](https://img.shields.io/badge/backend-Go%201.22-00add8?style=flat-square&logo=go)
![ebpf](https://img.shields.io/badge/kernel-eBPF-f60?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Every Node                                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  KubeRTSec Agent (DaemonSet)                             │  │
│  │  ┌────────────────────┐   ┌──────────────────────────┐  │  │
│  │  │  eBPF (execve      │   │  Rules Engine            │  │  │
│  │  │  tracepoint)       │──▶│  (YAML hot-reload)       │  │  │
│  │  └────────────────────┘   └────────────┬─────────────┘  │  │
│  │                                        │ POST /event     │  │
│  └────────────────────────────────────────┼────────────────┘  │
│                                           ▼                    │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  KubeRTSec Controller (Deployment)                        │ │
│  │  REST API + WebSocket + BoltDB store + Prometheus metrics │ │
│  └────────────────────────┬──────────────────────────────────┘ │
│                           │ nginx proxy                        │
│  ┌────────────────────────▼──────────────────────────────────┐ │
│  │  KubeRTSec Dashboard (React 19 + recharts)                │ │
│  │  Overview · Live Alerts · Pod Security · Metrics ·        │ │
│  │  Attack Timeline · Detection Rules                        │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Option A — Docker Compose (recommended for first try)

```bash
git clone https://github.com/Debasish-87/kubertsec.git
cd kubertsec

# Create .env (copy defaults)
cp .env.example .env

# Start controller + frontend (no eBPF required)
make dev
```

| Service      | URL                          |
|--------------|------------------------------|
| Dashboard    | http://localhost:3000        |
| Controller   | http://localhost:8080        |
| Prometheus   | http://localhost:9090 *(opt)*|
| Grafana      | http://localhost:3001 *(opt)*|

With full observability stack:

```bash
docker compose --profile monitoring up --build
```

---

### Option B — Native dev (3 terminals)

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

**Terminal 2 — eBPF Agent** (Linux only, requires root):
```bash
make agent
# or:
cd backend
sudo -E RESPONSE_MODE=alert \
  KUBESHIELD_CONTROLLER=http://localhost:8080/event \
  go run ./cmd/agent
```

**Terminal 3 — Dashboard:**
```bash
make frontend
# or:
cd frontend
cp .env.example .env.local
npm start
# Open http://localhost:3000
```

---

## Configuration

### Backend (controller + agent)

Copy `backend/env.example` → `backend/.env` and edit:

| Variable              | Default                       | Description                                   |
|-----------------------|-------------------------------|-----------------------------------------------|
| `LISTEN_ADDR`         | `:8080`                       | Controller listen address                     |
| `STORE_PATH`          | `/tmp/kubertsec-dev.db`       | BoltDB alert store path                       |
| `RULES_PATH`          | `configs/rules/process_rules.yaml` | Detection rules file                     |
| `ALLOWLIST_PATH`      | `configs/allowlist.yaml`      | Process allowlist                             |
| `RESPONSE_MODE`       | `alert`                       | `detect` / `alert` / `enforce`                |
| `KUBESHIELD_CONTROLLER` | `http://localhost:8080/event` | Agent → controller endpoint                 |
| `PROMETHEUS_URL`      | `http://localhost:9090`       | Prometheus for cluster metrics                |
| `GRAFANA_URL`         | `http://localhost:3001`       | Grafana base URL                              |
| `GRAFANA_USER`        | `admin`                       | Grafana username                              |
| `GRAFANA_PASSWORD`    | `admin123`                    | Grafana password                              |
| `GRAFANA_TOKEN`       | *(empty)*                     | Service account token (Grafana 10+, optional) |

### Frontend

Copy `frontend/.env.example` → `frontend/.env.local`:

| Variable                  | Default                     | Description                                              |
|---------------------------|-----------------------------|----------------------------------------------------------|
| `REACT_APP_API_URL`       | `http://localhost:8080`     | Controller URL (build-time; or use nginx proxy)          |
| `REACT_APP_WS_URL`        | `ws://localhost:8080/ws`    | WebSocket URL (auto-derived if not set)                  |
| `REACT_APP_STATS_INTERVAL`| `30000`                     | Stats polling interval (ms)                              |
| `REACT_APP_POD_INTERVAL`  | `15000`                     | Pod sync interval (ms)                                   |
| `REACT_APP_MAX_ALERTS`    | `500`                       | Max alerts kept in UI memory                             |

> **Production tip:** In Docker/K8s, leave `REACT_APP_API_URL` empty and let nginx proxy `/api/*` and `/ws` to the controller. Same image, any backend URL.

---

## Detection Rules

Rules live in `backend/configs/rules/process_rules.yaml`. Hot-reload via:
- File watcher (30s poll)  
- API: `POST /api/v1/rules/reload`  
- Dashboard: Rules page → ↺ Reload Rules

### Rule schema

```yaml
rules:
  - name: reverse_shell_nc          # unique name (used as alert rule_name)
    severity: critical              # critical | high | medium | low
    mode: enforce                   # detect | alert | enforce
    process_regex: "^nc$|^ncat$"   # regex matched against process name
    args_any:                       # alert if ANY of these appear in args
      - "-e /bin/bash"
      - "-e /bin/sh"
    message: "Reverse shell (netcat)"
    tags: [reverse_shell]
    namespaces:                     # limit to specific namespaces (optional)
      - production
    exclude_namespaces:             # ignore these namespaces (optional)
      - kube-system
```

### Response modes

| Mode      | What happens                                    |
|-----------|-------------------------------------------------|
| `detect`  | Log only — no network calls, no process kills   |
| `alert`   | Log + send event to controller                  |
| `enforce` | Log + send + `SIGKILL` the offending process    |

---

## API Reference

All endpoints served by the controller at `:8080`.

### Alerts

| Method | Path                         | Description                          |
|--------|------------------------------|--------------------------------------|
| GET    | `/api/v1/alerts`             | List alerts (filter + paginate)      |
| GET    | `/api/v1/alerts/stats`       | Aggregated counts by severity        |
| GET    | `/api/v1/alerts/:id`         | Single alert                         |
| PUT    | `/api/v1/alerts/:id/ack`     | Acknowledge alert                    |
| DELETE | `/api/v1/alerts/:id`         | Delete alert                         |

**Query params for `GET /api/v1/alerts`:**
`limit`, `offset`, `severity`, `namespace`, `pod`, `rule_name`, `process`, `since` (RFC3339), `until`, `acknowledged`

### Rules

| Method | Path                         | Description                          |
|--------|------------------------------|--------------------------------------|
| GET    | `/api/v1/rules`              | List all rules                       |
| POST   | `/api/v1/rules`              | Add rule (in-memory only)            |
| POST   | `/api/v1/rules/reload`       | Hot-reload from disk                 |
| GET    | `/api/v1/rules/:name`        | Get rule by name                     |
| DELETE | `/api/v1/rules/:name`        | Queue rule for deletion              |

### Other

| Method | Path                         | Description                          |
|--------|------------------------------|--------------------------------------|
| GET    | `/api/v1/pods`               | List monitored pods                  |
| GET    | `/api/v1/posture`            | Latest security posture report       |
| GET    | `/api/v1/status`             | Controller health + stats            |
| GET    | `/api/v1/metrics/cluster`    | Prometheus-backed cluster metrics    |
| GET    | `/ws`                        | WebSocket event stream               |
| POST   | `/event`                     | Agent event ingestion endpoint       |
| GET    | `/healthz`                   | Liveness probe                       |
| GET    | `/metrics`                   | Prometheus metrics (scrape target)   |

### WebSocket protocol

Connect to `ws://<controller>/ws`. On connect the server sends recent alerts:

```json
{ "type": "init", "data": [<Alert>, ...] }
```

On new event:

```json
{ "type": "alert", "data": <Alert> }
```

---

## Kubernetes Deployment

```bash
# 1. Edit image registry + secrets
vim deploy/kubernetes/kubertsec.yaml

# 2. Apply
kubectl apply -f deploy/kubernetes/kubertsec.yaml

# 3. Check rollout
kubectl rollout status deployment/kubertsec-controller -n kubertsec
kubectl rollout status deployment/kubertsec-frontend   -n kubertsec
kubectl rollout status daemonset/kubertsec-agent       -n kubertsec

# 4. Port-forward dashboard (until you configure Ingress)
kubectl port-forward svc/kubertsec-frontend -n kubertsec 3000:80
# Open http://localhost:3000
```

### Images

```bash
# Build
make docker-build REGISTRY=your-registry.io/your-org

# Push
make docker-push  REGISTRY=your-registry.io/your-org

# Or pull pre-built (GitHub Container Registry)
docker pull ghcr.io/debasish-87/kubertsec-controller:latest
docker pull ghcr.io/debasish-87/kubertsec-frontend:latest
```

---

## Prometheus & Grafana

### With port-forward (local development)

```bash
# Start port-forwards
make pf-start

# Prometheus → http://localhost:9090
# Grafana    → http://localhost:3001

# Stop
make pf-stop
```

### Metrics exposed by controller (`/metrics`)

| Metric                          | Type  | Description                        |
|---------------------------------|-------|------------------------------------|
| `kubertsec_alerts_total`        | gauge | Total alerts by `severity` label   |
| `kubertsec_alerts_last_hour`    | gauge | Alerts in last 60 minutes          |
| `kubertsec_monitored_pods`      | gauge | Pods currently visible             |
| `kubertsec_monitored_namespaces`| gauge | Active namespaces                  |
| `kubertsec_ws_clients`          | gauge | Active WebSocket connections       |
| `kubertsec_uptime_seconds`      | counter | Controller uptime                |

---

## Attack Simulation

Test your setup without a real attacker:

```bash
make attack-test
```

This runs `attack-test/attack-test.sh` which:

1. Spawns simulated attack processes (`curl`, `nc`, `xmrig`, `nsenter`, …) inside a test pod
2. Posts synthetic events to the controller
3. Triggers each detection rule

---

## Development

### Project structure

```
kubertsec/
├── backend/
│   ├── bpf/                    eBPF C programs
│   ├── cmd/
│   │   ├── agent/              eBPF agent binary
│   │   └── controller/         REST + WebSocket server
│   ├── pkg/
│   │   ├── correlation/        Multi-event attack correlation
│   │   ├── ebpf/               eBPF loader + event queue
│   │   ├── monitoring/         Prometheus + Grafana clients
│   │   ├── posture/            K8s security posture assessment
│   │   ├── response/           Process kill + allowlist
│   │   ├── rules/              YAML rule engine + watcher
│   │   ├── runtime/            Container + lineage tracking
│   │   └── store/              BoltDB alert store
│   └── configs/
│       ├── rules/process_rules.yaml
│       └── allowlist.yaml
├── frontend/
│   └── src/
│       ├── config/             Env-aware configuration
│       ├── services/           api.js · websocket.js
│       ├── store/              AppStore.js (useReducer)
│       ├── hooks/              useAPI · usePolling · useAction
│       ├── components/         UI.jsx · Toast.jsx
│       └── pages/              Overview · Alerts · Pods · Metrics
│                               Timeline · Rules
├── deploy/
│   └── kubernetes/kubertsec.yaml
├── monitoring/
│   ├── prometheus.yml
│   └── grafana/
├── docker-compose.yml          Production stack
├── docker-compose.override.yml Hot-reload dev overrides
├── Makefile
└── attack-test/
```

### Running tests

```bash
make test       # Go tests (race detector on)
make vet        # go vet
make fmt        # gofmt
make lint       # golangci-lint (if installed)
```

### Contributing

1. Fork → feature branch (`feat/your-feature`)
2. `make test` must pass
3. PR against `main` — describe what rule/detection/UI the change adds

---

## Security considerations

- The **agent** requires `privileged: true` and `hostPID: true` — this is inherent to eBPF kernel tracing. Review the DaemonSet manifest carefully before deploying to production.
- The **controller** runs as a non-root user (`UID 1000`) with a read-only root filesystem.
- The **frontend** container only serves static files and proxies to the controller — no direct kernel or K8s API access.
- Change `GRAFANA_PASSWORD` before deploying.
- In production, enable NetworkPolicy (included in the manifest) and add TLS via Ingress + cert-manager.

---

## License

MIT — see [LICENSE](LICENSE)
