#!/usr/bin/env bash
# ============================================================
#  KubeRTSec — One-Shot Installer
#  Works on: Ubuntu · Debian · Fedora · Arch · macOS
#  Installs: kubectl · kind · cluster · Prometheus · Grafana
#
#  Usage:  bash setup.sh
#  Options:
#    --skip-kind            Use existing cluster (don't create kind)
#    --namespace <ns>       Namespace (default: kubertsec)
#    --grafana-pass <pass>  Grafana password (default: admin123)
#    --no-port-forward      Skip auto port-forward
#    --dry-run              Print only, don't apply
# ============================================================
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[✓]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[✗]${NC}    $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${BLUE}━━━ $* ━━━${NC}"; }

echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗███████╗███████╗ ██████╗
██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔════╝
█████╔╝ ██║   ██║██████╔╝█████╗  ██████╔╝   ██║   ███████╗█████╗  ██║
██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗   ██║   ╚════██║██╔══╝  ██║
██║  ██╗╚██████╔╝██████╔╝███████╗██║  ██║   ██║   ███████║███████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝
              eBPF-powered Kubernetes Runtime Security
              Real-time threat detection · Automated response
BANNER
echo -e "${NC}"

# ── Defaults ──────────────────────────────────────────────────
NAMESPACE="kubertsec"
GRAFANA_ADMIN_PASS="admin123"
NO_PORT_FORWARD=false
DRY_RUN=false
SKIP_KIND=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --skip-kind)        SKIP_KIND=true;              shift ;;
    --namespace)        NAMESPACE="$2";              shift 2 ;;
    --grafana-pass)     GRAFANA_ADMIN_PASS="$2";     shift 2 ;;
    --no-port-forward)  NO_PORT_FORWARD=true;        shift ;;
    --dry-run)          DRY_RUN=true;                shift ;;
    -h|--help)
      echo "Usage: $0 [--skip-kind] [--namespace <ns>] [--grafana-pass <pass>]"
      echo "          [--no-port-forward] [--dry-run]"
      exit 0 ;;
    *) warn "Unknown option: $1"; shift ;;
  esac
done

kapply() {
  if [[ "$DRY_RUN" == "true" ]]; then cat; else kubectl apply -f -; fi
}

# ── Detect OS ─────────────────────────────────────────────────
OS="linux"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH_GO="amd64" ;;
  aarch64) ARCH_GO="arm64" ;;
  arm64)   ARCH_GO="arm64" ;;
  *)       ARCH_GO="amd64" ;;
esac

if [[ "$(uname -s)" == "Darwin" ]]; then
  OS="darwin"
fi

# ── Helper: install package ───────────────────────────────────
pkg_install() {
  local pkg="$1"
  if command -v apt-get &>/dev/null; then
    sudo apt-get install -y "$pkg" &>/dev/null
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y "$pkg" &>/dev/null
  elif command -v yum &>/dev/null; then
    sudo yum install -y "$pkg" &>/dev/null
  elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm "$pkg" &>/dev/null
  elif command -v brew &>/dev/null; then
    brew install "$pkg" &>/dev/null
  else
    warn "Could not install $pkg — please install manually"
    return 1
  fi
}

# ── Step 1: Install Dependencies ─────────────────────────────
step "Checking & Installing Dependencies"

# curl
if ! command -v curl &>/dev/null; then
  info "Installing curl..."
  pkg_install curl
fi
success "curl: $(curl --version | head -1)"

# docker (required for kind)
if ! command -v docker &>/dev/null; then
  error "Docker not found. Install Docker first: https://docs.docker.com/get-docker/"
fi
docker info &>/dev/null 2>&1 || error "Docker daemon not running — start Docker first"
success "Docker: $(docker --version)"

# kubectl
if ! command -v kubectl &>/dev/null; then
  info "Installing kubectl..."
  KUBECTL_VER=$(curl -Ls https://dl.k8s.io/release/stable.txt 2>/dev/null || echo "v1.30.0")
  curl -sLo /tmp/kubectl \
    "https://dl.k8s.io/release/${KUBECTL_VER}/bin/${OS}/${ARCH_GO}/kubectl"
  chmod +x /tmp/kubectl
  sudo mv /tmp/kubectl /usr/local/bin/kubectl
  success "kubectl installed: $KUBECTL_VER"
else
  success "kubectl: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1)"
fi

# kind — search common paths first, install if missing
KIND_BIN=""
for p in \
  "$(command -v kind 2>/dev/null || true)" \
  "$HOME/go/bin/kind" \
  "$HOME/Pictures/go/bin/kind" \
  "/usr/local/bin/kind" \
  "/usr/bin/kind"; do
  if [[ -x "$p" ]]; then
    KIND_BIN="$p"
    break
  fi
done

if [[ -z "$KIND_BIN" ]]; then
  info "kind not found — installing..."
  KIND_VER="v0.23.0"
  curl -sLo /tmp/kind \
    "https://kind.sigs.k8s.io/dl/${KIND_VER}/kind-${OS}-${ARCH_GO}"
  chmod +x /tmp/kind
  sudo mv /tmp/kind /usr/local/bin/kind
  KIND_BIN="/usr/local/bin/kind"
  success "kind installed: $KIND_VER"
else
  # Make sure it's in PATH
  KIND_DIR=$(dirname "$KIND_BIN")
  if ! command -v kind &>/dev/null; then
    export PATH="$PATH:$KIND_DIR"
    # Persist to bashrc/zshrc
    for RC in "$HOME/.bashrc" "$HOME/.zshrc"; do
      if [[ -f "$RC" ]] && ! grep -q "$KIND_DIR" "$RC" 2>/dev/null; then
        echo "export PATH=\"\$PATH:$KIND_DIR\"" >> "$RC"
        info "Added $KIND_DIR to $RC"
      fi
    done
  fi
  success "kind: $($KIND_BIN version)"
fi

# python3 (for verification steps)
if ! command -v python3 &>/dev/null; then
  info "Installing python3..."
  pkg_install python3
fi
success "python3: $(python3 --version)"

# ── Step 2: Cluster Setup ─────────────────────────────────────
step "Setting Up Kubernetes Cluster"

if [[ "$SKIP_KIND" == "true" ]]; then
  info "Skipping kind cluster creation (--skip-kind)"
  kubectl cluster-info &>/dev/null 2>&1 || error "No cluster reachable — check KUBECONFIG"
  success "Using existing cluster: $(kubectl config current-context)"
else
  # Check if cluster already exists and is healthy
  EXISTING_CLUSTER=$($KIND_BIN get clusters 2>/dev/null | head -1 || true)
  CLUSTER_HEALTHY=false

  if [[ -n "$EXISTING_CLUSTER" ]]; then
    info "Found existing kind cluster: $EXISTING_CLUSTER"
    # Check if it's actually reachable
    if kubectl cluster-info &>/dev/null 2>&1; then
      # Check CoreDNS is healthy
      COREDNS_OK=$(kubectl get pods -n kube-system -l k8s-app=kube-dns \
        --field-selector=status.phase=Running \
        --no-headers 2>/dev/null | wc -l || echo "0")
      if [[ "$COREDNS_OK" -gt 0 ]]; then
        CLUSTER_HEALTHY=true
        success "Existing cluster is healthy — reusing it"
      else
        warn "Existing cluster has broken CoreDNS — recreating..."
        $KIND_BIN delete cluster --name "$EXISTING_CLUSTER" 2>/dev/null || true
      fi
    else
      warn "Existing cluster is unreachable — recreating..."
      $KIND_BIN delete cluster --name "$EXISTING_CLUSTER" 2>/dev/null || true
    fi
  fi

  if [[ "$CLUSTER_HEALTHY" == "false" ]]; then
    info "Creating fresh kind cluster..."
    $KIND_BIN create cluster --wait 90s
    success "Kind cluster created"
  fi
fi

# ── Step 3: Wait for CoreDNS ──────────────────────────────────
# CoreDNS MUST be running before deploying Grafana.
# Without it, Grafana cannot reach Prometheus by service name,
# causing "dial tcp: lookup ... i/o timeout" errors.
step "Waiting for CoreDNS (required for Grafana → Prometheus)"

MAX_WAIT=120
WAITED=0
while true; do
  READY=$(kubectl get pods -n kube-system -l k8s-app=kube-dns \
    --field-selector=status.phase=Running \
    --no-headers 2>/dev/null | wc -l || echo "0")
  if [[ "$READY" -gt 0 ]]; then
    success "CoreDNS is running ($READY pod(s))"
    break
  fi
  if [[ "$WAITED" -ge "$MAX_WAIT" ]]; then
    warn "CoreDNS not ready after ${MAX_WAIT}s — continuing anyway (may affect Grafana)"
    break
  fi
  info "Waiting for CoreDNS... (${WAITED}s / ${MAX_WAIT}s)"
  sleep 5
  WAITED=$((WAITED + 5))
done

# ── Step 4: Detect cluster type & node IP ────────────────────
step "Detecting Cluster & Node IP"

CTX=$(kubectl config current-context 2>/dev/null || echo "unknown")
if   echo "$CTX" | grep -qi "kind";            then CLUSTER="kind"
elif echo "$CTX" | grep -qi "minikube";        then CLUSTER="minikube"
elif echo "$CTX" | grep -qi "k3d";             then CLUSTER="k3d"
elif echo "$CTX" | grep -qi "k3s";             then CLUSTER="k3s"
elif echo "$CTX" | grep -qi "docker-desktop";  then CLUSTER="docker-desktop"
elif echo "$CTX" | grep -qi "rancher-desktop"; then CLUSTER="rancher-desktop"
elif echo "$CTX" | grep -qi "gke";             then CLUSTER="gke"
elif echo "$CTX" | grep -qi "eks";             then CLUSTER="eks"
elif echo "$CTX" | grep -qi "aks";             then CLUSTER="aks"
else                                                 CLUSTER="generic"
fi
info "Cluster type: ${CLUSTER}"

# Auto-detect node IP — always use IP, never hostname
# Hostname-based Prometheus targets fail inside pods on kind/minikube
# because the node hostname is only resolvable from the host machine.
NODE_IP=$(kubectl get nodes \
  -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' \
  2>/dev/null || true)

if [[ -z "$NODE_IP" ]]; then
  NODE_IP=$(kubectl get nodes \
    -o jsonpath='{.items[0].status.addresses[?(@.type=="ExternalIP")].address}' \
    2>/dev/null || true)
fi

if [[ -z "$NODE_IP" ]] && [[ "$CLUSTER" == "kind" ]]; then
  NODE_IP=$(docker inspect kind-control-plane \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    2>/dev/null || true)
fi

if [[ -n "$NODE_IP" ]]; then
  success "Node IP: ${NODE_IP}"
  USE_STATIC_IP=true
else
  warn "Could not detect node IP — using kubernetes_sd_configs"
  USE_STATIC_IP=false
fi

# ── Step 5: Namespaces ────────────────────────────────────────
step "Creating Namespaces"
for NS in "$NAMESPACE" monitoring; do
  if kubectl get namespace "$NS" &>/dev/null 2>&1; then
    info "Namespace '${NS}' already exists"
  else
    kubectl create namespace "$NS"
    success "Created: ${NS}"
  fi
done

# ── Step 6: RBAC ──────────────────────────────────────────────
step "Configuring RBAC"
cat << EOF | kapply
apiVersion: v1
kind: ServiceAccount
metadata:
  name: prometheus-sa
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubertsec-prometheus
rules:
- apiGroups: [""]
  resources: [nodes, nodes/proxy, nodes/metrics, services, endpoints, pods]
  verbs: [get, list, watch]
- nonResourceURLs: [/metrics, /metrics/cadvisor]
  verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubertsec-prometheus
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubertsec-prometheus
subjects:
- kind: ServiceAccount
  name: prometheus-sa
  namespace: monitoring
EOF
success "RBAC configured"

# ── Step 7: Prometheus ────────────────────────────────────────
step "Installing Prometheus"

if [[ "$USE_STATIC_IP" == "true" ]]; then
  info "Scrape config: static IP (${NODE_IP})"
  SCRAPE_CONFIG="
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['${NODE_IP}:10250']
    scheme: https
    tls_config:
      insecure_skip_verify: true
    authorization:
      credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    metrics_path: /metrics/cadvisor

  - job_name: 'kubelet'
    static_configs:
      - targets: ['${NODE_IP}:10250']
    scheme: https
    tls_config:
      insecure_skip_verify: true
    authorization:
      credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    metrics_path: /metrics
"
else
  info "Scrape config: kubernetes_sd_configs"
  AUTH_BLOCK="authorization:
          credentials_file: /var/run/secrets/kubernetes.io/serviceaccount/token"
  SCRAPE_CONFIG="
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'cadvisor'
    scheme: https
    tls_config:
      insecure_skip_verify: true
    ${AUTH_BLOCK}
    kubernetes_sd_configs:
      - role: node
    metrics_path: /metrics/cadvisor
    relabel_configs:
      - source_labels: [__address__]
        regex: '([^:]+)(?::\d+)?'
        target_label: __address__
        replacement: '\${1}:10250'
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)

  - job_name: 'kubelet'
    scheme: https
    tls_config:
      insecure_skip_verify: true
    ${AUTH_BLOCK}
    kubernetes_sd_configs:
      - role: node
    relabel_configs:
      - source_labels: [__address__]
        regex: '([^:]+)(?::\d+)?'
        target_label: __address__
        replacement: '\${1}:10250'
      - action: labelmap
        regex: __meta_kubernetes_node_label_(.+)
"
fi

kubectl create configmap prometheus-config \
  --namespace monitoring \
  --dry-run=client -o yaml \
  --from-literal=prometheus.yml="${SCRAPE_CONFIG}" \
  | kubectl apply -f -
success "Prometheus ConfigMap applied"

cat << EOF | kapply
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: monitoring
  labels:
    app: prometheus
    component: kubertsec
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      serviceAccountName: prometheus-sa
      containers:
      - name: prometheus
        image: prom/prometheus:latest
        args:
          - --config.file=/etc/prometheus/prometheus.yml
          - --storage.tsdb.path=/prometheus
          - --web.enable-lifecycle
          - --storage.tsdb.retention.time=7d
        ports:
        - name: http
          containerPort: 9090
        volumeMounts:
        - name: config
          mountPath: /etc/prometheus
        - name: storage
          mountPath: /prometheus
        resources:
          requests: {memory: "256Mi", cpu: "100m"}
          limits:   {memory: "512Mi", cpu: "500m"}
        readinessProbe:
          httpGet: {path: /-/ready, port: 9090}
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          httpGet: {path: /-/healthy, port: 9090}
          initialDelaySeconds: 30
          periodSeconds: 15
      volumes:
      - name: config
        configMap:
          name: prometheus-config
      - name: storage
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: prometheus-svc
  namespace: monitoring
  labels:
    app: prometheus
    component: kubertsec
spec:
  selector:
    app: prometheus
  ports:
  - name: http
    port: 9090
    targetPort: 9090
EOF
success "Prometheus deployed"

# Wait for Prometheus to be ready before getting its ClusterIP
kubectl rollout status deployment/prometheus -n monitoring --timeout=180s \
  && success "Prometheus ready" \
  || warn "Prometheus slow — check: kubectl get pods -n monitoring"

# ── Step 8: Grafana datasource URL ───────────────────────────
# Use DNS name if CoreDNS healthy, else ClusterIP
PROM_CLUSTER_IP=$(kubectl get svc prometheus-svc -n monitoring \
  -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)

COREDNS_COUNT=$(kubectl get pods -n kube-system -l k8s-app=kube-dns \
  --field-selector=status.phase=Running \
  --no-headers 2>/dev/null | wc -l || echo "0")

if [[ "$COREDNS_COUNT" -gt 0 ]]; then
  GRAFANA_PROM_URL="http://prometheus-svc.monitoring.svc.cluster.local:9090"
  info "Grafana datasource: DNS (${GRAFANA_PROM_URL})"
elif [[ -n "$PROM_CLUSTER_IP" ]]; then
  GRAFANA_PROM_URL="http://${PROM_CLUSTER_IP}:9090"
  warn "CoreDNS unavailable — using ClusterIP: ${GRAFANA_PROM_URL}"
else
  GRAFANA_PROM_URL="http://prometheus-svc.monitoring.svc.cluster.local:9090"
fi

# ── Step 9: Grafana ───────────────────────────────────────────
step "Installing Grafana"

cat << EOF | kapply
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasource
  namespace: monitoring
data:
  datasource.yaml: |
    apiVersion: 1
    datasources:
      - name: Prometheus
        type: prometheus
        uid: prometheus
        url: ${GRAFANA_PROM_URL}
        access: proxy
        isDefault: true
        editable: true
        jsonData:
          httpMethod: POST
          timeInterval: "15s"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: monitoring
  labels:
    app: grafana
    component: kubertsec
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      containers:
      - name: grafana
        image: grafana/grafana:latest
        ports:
        - name: http
          containerPort: 3000
        env:
        - name: GF_SECURITY_ADMIN_PASSWORD
          value: "${GRAFANA_ADMIN_PASS}"
        - name: GF_AUTH_ANONYMOUS_ENABLED
          value: "true"
        - name: GF_AUTH_ANONYMOUS_ORG_ROLE
          value: "Viewer"
        - name: GF_SECURITY_ALLOW_EMBEDDING
          value: "true"
        - name: GF_USERS_DEFAULT_THEME
          value: "dark"
        volumeMounts:
        - name: datasource
          mountPath: /etc/grafana/provisioning/datasources
        resources:
          requests: {memory: "128Mi", cpu: "100m"}
          limits:   {memory: "256Mi", cpu: "200m"}
        readinessProbe:
          httpGet: {path: /api/health, port: 3000}
          initialDelaySeconds: 15
          periodSeconds: 5
      volumes:
      - name: datasource
        configMap:
          name: grafana-datasource
---
apiVersion: v1
kind: Service
metadata:
  name: grafana-svc
  namespace: monitoring
  labels:
    app: grafana
    component: kubertsec
spec:
  selector:
    app: grafana
  ports:
  - name: http
    port: 3000
    targetPort: 3000
EOF

kubectl rollout status deployment/grafana -n monitoring --timeout=180s \
  && success "Grafana ready" \
  || warn "Grafana slow — check: kubectl get pods -n monitoring"

# ── Step 10: Port Forwards ────────────────────────────────────
if [[ "$DRY_RUN" == "false" ]] && [[ "$NO_PORT_FORWARD" == "false" ]]; then
  step "Starting Port Forwards"

  pkill -f "port-forward.*prometheus-svc" 2>/dev/null || true
  pkill -f "port-forward.*grafana-svc"    2>/dev/null || true
  fuser -k 9090/tcp &>/dev/null 2>&1 || true
  fuser -k 3001/tcp &>/dev/null 2>&1 || true
  sleep 2

  kubectl port-forward svc/prometheus-svc -n monitoring 9090:9090 &>/dev/null &
  PF_PROM_PID=$!
  kubectl port-forward svc/grafana-svc    -n monitoring 3001:3000 &>/dev/null &
  PF_GRAF_PID=$!
  sleep 3

  kill -0 "$PF_PROM_PID" 2>/dev/null \
    && success "Prometheus port-forward → http://localhost:9090 (pid ${PF_PROM_PID})" \
    || warn "Prometheus port-forward failed — run: kubectl port-forward svc/prometheus-svc -n monitoring 9090:9090"

  kill -0 "$PF_GRAF_PID" 2>/dev/null \
    && success "Grafana port-forward → http://localhost:3001 (pid ${PF_GRAF_PID})" \
    || warn "Grafana port-forward failed — run: kubectl port-forward svc/grafana-svc -n monitoring 3001:3000"
fi

# ── Step 11: Verify Prometheus targets ───────────────────────
step "Verifying Prometheus Targets"
sleep 8

TARGETS=$(curl -s "http://localhost:9090/api/v1/targets" 2>/dev/null | \
  python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  for t in d.get('data',{}).get('activeTargets',[]):
    print(t.get('labels',{}).get('job','?'), '->', t.get('health','?'))
except: pass
" 2>/dev/null || echo "")

ALL_UP=true
if [[ -n "$TARGETS" ]]; then
  while IFS= read -r line; do
    if [[ "$line" == *"up"* ]]; then
      success "Target: $line"
    else
      warn "Target DOWN: $line"
      ALL_UP=false
    fi
  done <<< "$TARGETS"
else
  warn "Could not verify Prometheus targets yet"
  ALL_UP=false
fi

# ── Step 12: Verify Grafana datasource ───────────────────────
step "Verifying Grafana Datasource"
sleep 3

DS_STATUS=$(curl -s -X POST \
  "http://localhost:3001/api/datasources/uid/prometheus/health" \
  -u "admin:${GRAFANA_ADMIN_PASS}" \
  -H "Content-Type: application/json" 2>/dev/null | \
  python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  print(d.get('status','?'), '-', d.get('message','')[:80])
except: print('could not parse')
" 2>/dev/null || echo "could not reach Grafana")

if echo "$DS_STATUS" | grep -qi "ok\|success"; then
  success "Grafana → Prometheus: ${DS_STATUS}"
else
  warn "Grafana datasource: ${DS_STATUS}"
  warn "This will auto-fix when controller starts (it pushes correct ClusterIP)"
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║        KubeRTSec Setup Complete! 🎉                    ║${NC}"
echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Cluster${NC}      → ${CLUSTER}"
[[ -n "${NODE_IP:-}" ]] && echo -e "  ${CYAN}Node IP${NC}      → ${NODE_IP}"
echo -e "  ${CYAN}Prometheus${NC}   → http://localhost:9090"
echo -e "  ${CYAN}Grafana${NC}      → http://localhost:3001  (admin / ${GRAFANA_ADMIN_PASS})"
echo ""
if [[ "$ALL_UP" == "true" ]]; then
  echo -e "  ${GREEN}${BOLD}All Prometheus targets UP ✓${NC}"
else
  echo -e "  ${YELLOW}Some targets may still be starting — wait 30s then: make dev${NC}"
fi
echo ""
echo -e "${BOLD}Next — open 3 terminals:${NC}"
echo ""
echo -e "  ${CYAN}Terminal 1${NC}  (Controller):"
echo -e "  ${BOLD}make controller${NC}"
echo ""
echo -e "  ${CYAN}Terminal 2${NC}  (Agent — needs sudo for eBPF):"
echo -e "  ${BOLD}make agent${NC}"
echo ""
echo -e "  ${CYAN}Terminal 3${NC}  (Dashboard):"
echo -e "  ${BOLD}make frontend${NC}   →  http://localhost:3000"
echo ""
echo -e "  ${CYAN}Port-forward lost?${NC}   ${BOLD}make pf-start${NC}"
echo -e "  ${CYAN}Check status?${NC}        ${BOLD}make status${NC}"
echo -e "  ${CYAN}Uninstall?${NC}           ${BOLD}bash uninstall.sh${NC}"
echo ""

