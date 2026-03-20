#!/usr/bin/env bash
# ================================================================
#  KubeRTSec — Production One-Command Installer
#  eBPF-powered Kubernetes Runtime Security Platform
#
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/Debasish-87/kubertsec/main/install.sh | bash
#
#    OR after cloning:
#    bash install.sh
#
#  What this script does (fully automatic):
#    1.  Detects OS + installs system dependencies
#    2.  Installs Docker (if missing)
#    3.  Installs Go 1.24 (if missing)
#    4.  Installs kubectl + kind (if missing)
#    5.  Installs clang/llvm/bpftool (for eBPF)
#    6.  Creates kind cluster (if no cluster exists)
#    7.  Deploys Prometheus + Grafana into cluster
#    8.  Compiles eBPF BPF object (vmlinux.h + clang)
#    9.  Generates Docker-compatible kubeconfig
#    10. Creates .env with all correct URLs
#    11. Starts full stack via docker compose
#    12. Creates /usr/local/bin/kubertsec CLI helper
#    13. Sets up systemd service for auto-start on boot
#
#  After install:
#    Dashboard   → http://localhost:3000
#    Controller  → http://localhost:8080
#    Prometheus  → http://localhost:9090
#    Grafana     → http://localhost:3001
# ================================================================
set -euo pipefail

# ── Terminal colors ──────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  BOLD='\033[1m';    NC='\033[0m'

info()    { echo -e "${CYAN}  ▶${NC} $*"; }
success() { echo -e "${GREEN}  ✓${NC} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${NC} $*"; }
error()   { echo -e "${RED}  ✗ ERROR:${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
            echo -e "${BOLD}${BLUE}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# ── Banner ───────────────────────────────────────────────────────
echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗███████╗███████╗ ██████╗
  ██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔════╝
  █████╔╝ ██║   ██║██████╔╝█████╗  ██████╔╝   ██║   ███████╗█████╗  ██║
  ██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗   ██║   ╚════██║██╔══╝  ██║
  ██║  ██╗╚██████╔╝██████╔╝███████╗██║  ██║   ██║   ███████║███████╗╚██████╗
  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝

          eBPF-powered Kubernetes Runtime Security Platform
             Real-time threat detection · Automated response
BANNER
echo -e "${NC}"
echo -e "  ${BOLD}Version:${NC} 1.0.0   ${BOLD}Author:${NC} Debasish Mohanty"
echo ""

# ── Detect script location ───────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$SCRIPT_DIR"

# ── Detect OS ────────────────────────────────────────────────────
detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_FAMILY="${ID_LIKE:-$ID}"
  elif [[ "$(uname)" == "Darwin" ]]; then
    OS_ID="macos"
    OS_FAMILY="macos"
  else
    OS_ID="unknown"
    OS_FAMILY="unknown"
  fi
  ARCH="$(uname -m)"
}
detect_os

info "Detected OS: ${OS_ID} (${ARCH})"

# ── Package manager ──────────────────────────────────────────────
pkg_install() {
  case "$OS_FAMILY" in
    *debian*|*ubuntu*)   sudo apt-get install -y -qq "$@" ;;
    *fedora*|*rhel*|*centos*) sudo dnf install -y -q "$@" ;;
    *arch*)              sudo pacman -S --noconfirm --quiet "$@" ;;
    macos)               brew install "$@" ;;
    *) warn "Unknown package manager — please install manually: $*" ;;
  esac
}

pkg_update() {
  case "$OS_FAMILY" in
    *debian*|*ubuntu*)   sudo apt-get update -qq ;;
    *fedora*|*rhel*|*centos*) sudo dnf check-update -q || true ;;
    *arch*)              sudo pacman -Sy --quiet ;;
    macos)               brew update ;;
  esac
}

# ════════════════════════════════════════════════════════════════
# STEP 1 — System dependencies
# ════════════════════════════════════════════════════════════════
step "Step 1/10 — Installing System Dependencies"

pkg_update 2>/dev/null || true

MISSING_PKGS=()

command -v curl    &>/dev/null || MISSING_PKGS+=(curl)
command -v wget    &>/dev/null || MISSING_PKGS+=(wget)
command -v git     &>/dev/null || MISSING_PKGS+=(git)
command -v python3 &>/dev/null || MISSING_PKGS+=(python3)
command -v jq      &>/dev/null || MISSING_PKGS+=(jq)

[[ ${#MISSING_PKGS[@]} -gt 0 ]] && pkg_install "${MISSING_PKGS[@]}"
success "Base tools ready"

# ════════════════════════════════════════════════════════════════
# STEP 2 — Docker
# ════════════════════════════════════════════════════════════════
step "Step 2/10 — Docker"

if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  if [[ "$OS_FAMILY" == *"debian"* ]] || [[ "$OS_FAMILY" == *"ubuntu"* ]]; then
    curl -fsSL https://get.docker.com | sudo bash
    sudo usermod -aG docker "$USER"
    warn "Docker installed. You may need to re-login for group changes."
    # Use sudo docker for rest of script
    DOCKER_CMD="sudo docker"
    COMPOSE_CMD="sudo docker compose"
  elif [[ "$OS_ID" == "macos" ]]; then
    error "Please install Docker Desktop for Mac: https://docs.docker.com/desktop/install/mac-install/"
  else
    curl -fsSL https://get.docker.com | sudo bash
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER"
    DOCKER_CMD="sudo docker"
    COMPOSE_CMD="sudo docker compose"
  fi
else
  DOCKER_CMD="docker"
  COMPOSE_CMD="docker compose"
  # Check if user can run docker without sudo
  if ! docker info &>/dev/null 2>&1; then
    DOCKER_CMD="sudo docker"
    COMPOSE_CMD="sudo docker compose"
  fi
fi

# Verify docker compose v2
if ! $DOCKER_CMD compose version &>/dev/null 2>&1; then
  info "Installing docker-compose-plugin..."
  pkg_install docker-compose-plugin 2>/dev/null || \
  pkg_install docker-compose 2>/dev/null || \
  warn "docker compose plugin not found — trying standalone"
fi

success "Docker: $($DOCKER_CMD --version 2>/dev/null | head -1)"

# ════════════════════════════════════════════════════════════════
# STEP 3 — Go 1.24
# ════════════════════════════════════════════════════════════════
step "Step 3/10 — Go Language Runtime"

GO_MIN="1.24"

go_ok() {
  if command -v go &>/dev/null; then
    local ver
    ver=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
    python3 -c "import sys; v='$ver'.split('.'); m='$GO_MIN'.split('.'); sys.exit(0 if (int(v[0]),int(v[1])) >= (int(m[0]),int(m[1])) else 1)"
  else
    return 1
  fi
}

if go_ok; then
  success "Go $(go version | awk '{print $3}') already installed"
else
  info "Installing Go ${GO_MIN}..."
  GO_VER="1.24.1"
  case "$ARCH" in
    x86_64)  GO_ARCH="amd64" ;;
    aarch64) GO_ARCH="arm64" ;;
    armv7l)  GO_ARCH="armv6l" ;;
    *)       error "Unsupported arch: $ARCH" ;;
  esac
  GO_TAR="go${GO_VER}.linux-${GO_ARCH}.tar.gz"
  wget -q "https://go.dev/dl/${GO_TAR}" -O /tmp/${GO_TAR}
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/${GO_TAR}
  rm /tmp/${GO_TAR}

  # Add to PATH permanently
  if ! grep -q "/usr/local/go/bin" ~/.bashrc 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  fi
  if ! grep -q "/usr/local/go/bin" ~/.profile 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
  fi
  export PATH=$PATH:/usr/local/go/bin
  success "Go $(go version | awk '{print $3}') installed"
fi

# ════════════════════════════════════════════════════════════════
# STEP 4 — kubectl + kind
# ════════════════════════════════════════════════════════════════
step "Step 4/10 — Kubernetes Tools (kubectl + kind)"

# kubectl
if ! command -v kubectl &>/dev/null; then
  info "Installing kubectl..."
  KUBECTL_VER=$(curl -sL https://dl.k8s.io/release/stable.txt)
  case "$ARCH" in
    x86_64)  KA="amd64" ;;
    aarch64) KA="arm64" ;;
    *)       KA="amd64" ;;
  esac
  sudo curl -sLo /usr/local/bin/kubectl \
    "https://dl.k8s.io/release/${KUBECTL_VER}/bin/linux/${KA}/kubectl"
  sudo chmod +x /usr/local/bin/kubectl
  success "kubectl $(kubectl version --client --short 2>/dev/null | head -1)"
else
  success "kubectl $(kubectl version --client --short 2>/dev/null | head -1)"
fi

# kind
if ! command -v kind &>/dev/null; then
  info "Installing kind..."
  case "$ARCH" in
    x86_64)  KA="amd64" ;;
    aarch64) KA="arm64" ;;
    *)       KA="amd64" ;;
  esac
  KIND_VER=$(curl -sL https://api.github.com/repos/kubernetes-sigs/kind/releases/latest \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])")
  sudo curl -sLo /usr/local/bin/kind \
    "https://kind.sigs.k8s.io/dl/${KIND_VER}/kind-linux-${KA}"
  sudo chmod +x /usr/local/bin/kind
  success "kind $(kind version)"
else
  success "kind $(kind version)"
fi

# ════════════════════════════════════════════════════════════════
# STEP 5 — eBPF Tools (clang, llvm, bpftool, libbpf)
# ════════════════════════════════════════════════════════════════
step "Step 5/10 — eBPF Compilation Tools"

BPF_PKGS=()
command -v clang   &>/dev/null || BPF_PKGS+=(clang)
command -v llvm-ar &>/dev/null || BPF_PKGS+=(llvm)
command -v bpftool &>/dev/null || {
  case "$OS_FAMILY" in
    *debian*|*ubuntu*) BPF_PKGS+=(linux-tools-common "linux-tools-$(uname -r)" "linux-headers-$(uname -r)") ;;
    *fedora*|*rhel*)   BPF_PKGS+=(bpftool kernel-devel) ;;
    *arch*)            BPF_PKGS+=(bpf) ;;
  esac
}

# libbpf-dev
case "$OS_FAMILY" in
  *debian*|*ubuntu*) BPF_PKGS+=(libbpf-dev) ;;
  *fedora*|*rhel*)   BPF_PKGS+=(libbpf-devel) ;;
  *arch*)            BPF_PKGS+=(libbpf) ;;
esac

[[ ${#BPF_PKGS[@]} -gt 0 ]] && { info "Installing eBPF tools..."; pkg_install "${BPF_PKGS[@]}" 2>/dev/null || true; }

# Verify bpftool
if ! command -v bpftool &>/dev/null; then
  # Try alternate locations
  for f in /usr/lib/linux-tools/*/bpftool /usr/sbin/bpftool; do
    [[ -x "$f" ]] && { sudo ln -sf "$f" /usr/local/bin/bpftool; break; }
  done
fi

command -v clang &>/dev/null   && success "clang $(clang --version | head -1 | grep -oP '\d+\.\d+\.\d+')"
command -v bpftool &>/dev/null && success "bpftool available"

# ════════════════════════════════════════════════════════════════
# STEP 6 — Compile eBPF object
# ════════════════════════════════════════════════════════════════
step "Step 6/10 — Compiling eBPF Program"

BPF_DIR="${INSTALL_DIR}/backend/bpf"
BPF_SRC="${BPF_DIR}/execve.bpf.c"
BPF_OBJ="${BPF_DIR}/execve.bpf.o"
VMLINUX="${BPF_DIR}/vmlinux.h"

if [[ ! -f "$VMLINUX" ]]; then
  info "Generating vmlinux.h from running kernel..."
  if [[ -f /sys/kernel/btf/vmlinux ]]; then
    sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX"
    success "vmlinux.h generated ($(wc -l < "$VMLINUX") lines)"
  else
    warn "BTF not available — eBPF agent will run in limited mode"
    touch "$VMLINUX"
  fi
fi

if [[ ! -f "$BPF_OBJ" ]] && command -v clang &>/dev/null; then
  info "Compiling eBPF object..."
  clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I"${BPF_DIR}" \
    -c "${BPF_SRC}" \
    -o "${BPF_OBJ}" 2>&1 && \
  success "eBPF compiled: $(ls -lh "$BPF_OBJ" | awk '{print $5}')" || \
  warn "eBPF compilation failed — agent will start without kernel probes"
fi

# ════════════════════════════════════════════════════════════════
# STEP 7 — Kubernetes cluster
# ════════════════════════════════════════════════════════════════
step "Step 7/10 — Kubernetes Cluster"

# Check if any cluster is available
if kubectl cluster-info &>/dev/null 2>&1; then
  CLUSTER=$(kubectl config current-context)
  success "Using existing cluster: ${CLUSTER}"
else
  info "Creating kind cluster 'kubertsec'..."
  cat > /tmp/kind-config.yaml << 'KIND_EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: kubertsec
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30000
        hostPort: 30000
        protocol: TCP
KIND_EOF
  kind create cluster --config /tmp/kind-config.yaml
  kubectl config use-context kind-kubertsec
  CLUSTER="kind-kubertsec"
  success "Cluster created: ${CLUSTER}"
fi

# ════════════════════════════════════════════════════════════════
# STEP 8 — Prometheus + Grafana in cluster
# ════════════════════════════════════════════════════════════════
step "Step 8/10 — Deploying Prometheus + Grafana"

# Create monitoring namespace
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f - &>/dev/null
success "Namespace: monitoring"

# Deploy Prometheus (if not exists)
if ! kubectl get deployment prometheus -n monitoring &>/dev/null 2>&1; then
  info "Deploying Prometheus..."
  cat << 'PROM_EOF' | kubectl apply -f - &>/dev/null
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: monitoring
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
      containers:
        - name: prometheus
          image: prom/prometheus:v2.51.0
          args:
            - --config.file=/etc/prometheus/prometheus.yml
            - --storage.tsdb.path=/prometheus
            - --storage.tsdb.retention.time=7d
            - --web.enable-lifecycle
          ports:
            - containerPort: 9090
          volumeMounts:
            - name: config
              mountPath: /etc/prometheus
      volumes:
        - name: config
          configMap:
            name: prometheus-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    scrape_configs:
      - job_name: prometheus
        static_configs:
          - targets: ['localhost:9090']
      - job_name: kubertsec-controller
        static_configs:
          - targets: ['host.docker.internal:8080']
        metrics_path: /metrics
---
apiVersion: v1
kind: Service
metadata:
  name: prometheus-svc
  namespace: monitoring
spec:
  selector:
    app: prometheus
  ports:
    - port: 9090
      targetPort: 9090
PROM_EOF
  success "Prometheus deployed"
else
  success "Prometheus already running"
fi

# Deploy Grafana (if not exists)
if ! kubectl get deployment grafana -n monitoring &>/dev/null 2>&1; then
  info "Deploying Grafana..."
  cat << 'GRAF_EOF' | kubectl apply -f - &>/dev/null
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: monitoring
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
          image: grafana/grafana:10.4.0
          env:
            - name: GF_SECURITY_ADMIN_USER
              value: "admin"
            - name: GF_SECURITY_ADMIN_PASSWORD
              value: "admin123"
            - name: GF_AUTH_ANONYMOUS_ENABLED
              value: "false"
          ports:
            - containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: grafana-svc
  namespace: monitoring
spec:
  selector:
    app: grafana
  ports:
    - port: 3000
      targetPort: 3000
GRAF_EOF
  GRAFANA_PASS="admin123"
  success "Grafana deployed (admin / admin123)"
else
  GRAFANA_PASS="${GRAFANA_PASS:-admin123}"
  success "Grafana already running"
fi

# Wait for pods to be ready
info "Waiting for monitoring pods to be ready..."
kubectl wait --for=condition=ready pod -l app=prometheus -n monitoring --timeout=120s &>/dev/null || \
  warn "Prometheus pod not ready yet — continuing anyway"
kubectl wait --for=condition=ready pod -l app=grafana -n monitoring --timeout=120s &>/dev/null || \
  warn "Grafana pod not ready yet — continuing anyway"
success "Monitoring stack ready"

# ════════════════════════════════════════════════════════════════
# STEP 9 — Port-forwards + kubeconfig
# ════════════════════════════════════════════════════════════════
step "Step 9/10 — Port-Forwards + Kubeconfig"

# Kill existing port-forwards
pkill -f "port-forward.*prometheus" 2>/dev/null || true
pkill -f "port-forward.*grafana"    2>/dev/null || true
sleep 1

# Start port-forwards
kubectl port-forward svc/prometheus-svc -n monitoring 9090:9090 \
  >/tmp/pf-prometheus.log 2>&1 &
PF_PROM=$!

kubectl port-forward svc/grafana-svc -n monitoring 3001:3000 \
  >/tmp/pf-grafana.log 2>&1 &
PF_GRAF=$!

sleep 3

kill -0 $PF_PROM 2>/dev/null && success "Prometheus → http://localhost:9090" || warn "Prometheus port-forward issue"
kill -0 $PF_GRAF 2>/dev/null && success "Grafana    → http://localhost:3001" || warn "Grafana port-forward issue"

success "Port-forwards active"

# ════════════════════════════════════════════════════════════════
# STEP 10 — Create .env + start docker compose
# ════════════════════════════════════════════════════════════════
step "Step 10/10 — Configuring & Starting KubeRTSec"

# Create .env
cat > "${INSTALL_DIR}/.env" << ENV_EOF
# KubeRTSec — Auto-generated by install.sh
VERSION=1.0.0

LISTEN_ADDR=:8080
STORE_PATH=/data/alerts.db
RULES_PATH=/configs/rules/process_rules.yaml
ALLOWLIST_PATH=/configs/allowlist.yaml
RESPONSE_MODE=alert

PROMETHEUS_URL=http://localhost:9090
GRAFANA_URL=http://localhost:3001
GRAFANA_USER=admin
GRAFANA_PASSWORD=${GRAFANA_PASS:-admin123}
GRAFANA_TOKEN=
GRAFANA_PUBLIC_URL=http://localhost:3001

REACT_APP_API_URL=http://localhost:8080
REACT_APP_WS_URL=ws://localhost:8080/ws
ENV_EOF

success ".env created"

# Start docker compose (controller + frontend)
info "Building and starting KubeRTSec (this may take 2-3 minutes first time)..."
cd "${INSTALL_DIR}"

# Stop any existing stack
$COMPOSE_CMD down &>/dev/null 2>&1 || true

# Build + start
$COMPOSE_CMD up --build -d

# Wait for controller to be healthy
info "Waiting for controller to start..."
for i in {1..30}; do
  if curl -sf http://localhost:8080/healthz &>/dev/null; then
    success "Controller is up!"
    break
  fi
  sleep 2
  [[ $i -eq 30 ]] && warn "Controller taking longer than expected — check: docker compose logs controller"
done

# ════════════════════════════════════════════════════════════════
# Create /usr/local/bin/kubertsec CLI helper
# ════════════════════════════════════════════════════════════════

sudo tee /usr/local/bin/kubertsec > /dev/null << CLISCRIPT
#!/usr/bin/env bash
# KubeRTSec CLI Helper
INSTALL_DIR="${INSTALL_DIR}"

case "\${1:-help}" in
  start)
    cd "\$INSTALL_DIR"
    # Restart port-forwards if needed
    if ! curl -sf http://localhost:9090/-/healthy &>/dev/null; then
      kubectl port-forward svc/prometheus-svc -n monitoring 9090:9090 >/tmp/pf-prometheus.log 2>&1 &
    fi
    if ! curl -sf http://localhost:3001/api/health &>/dev/null; then
      kubectl port-forward svc/grafana-svc -n monitoring 3001:3000 >/tmp/pf-grafana.log 2>&1 &
    fi
    docker compose up -d
    echo "KubeRTSec started → http://localhost:3000"
    ;;
  stop)
    cd "\$INSTALL_DIR"
    docker compose down
    pkill -f "port-forward.*prometheus" 2>/dev/null || true
    pkill -f "port-forward.*grafana"    2>/dev/null || true
    echo "KubeRTSec stopped"
    ;;
  agent)
    cd "\$INSTALL_DIR/backend"
    sudo -E KUBECONFIG=\$HOME/.kube/config \
      RESPONSE_MODE=alert \
      RULES_PATH=\$PWD/configs/rules/process_rules.yaml \
      ALLOWLIST_PATH=\$PWD/configs/allowlist.yaml \
      KUBESHIELD_CONTROLLER=http://localhost:8080/event \
      go run ./cmd/agent
    ;;
  status)
    echo "=== KubeRTSec Status ==="
    curl -sf http://localhost:8080/api/v1/status | python3 -m json.tool 2>/dev/null || echo "Controller offline"
    echo ""
    echo "=== K8s Pods ==="
    kubectl get pods -A 2>/dev/null || echo "kubectl unavailable"
    ;;
  logs)
    cd "\$INSTALL_DIR"
    docker compose logs -f --tail=50
    ;;
  dashboard)
    xdg-open http://localhost:3000 2>/dev/null || echo "Open: http://localhost:3000"
    ;;
  pf-start)
    kubectl port-forward svc/prometheus-svc -n monitoring 9090:9090 >/tmp/pf-prometheus.log 2>&1 &
    kubectl port-forward svc/grafana-svc    -n monitoring 3001:3000 >/tmp/pf-grafana.log 2>&1 &
    sleep 2
    echo "Prometheus → http://localhost:9090"
    echo "Grafana    → http://localhost:3001"
    ;;
  uninstall)
    cd "\$INSTALL_DIR"
    docker compose down -v
    pkill -f "port-forward" 2>/dev/null || true
    sudo rm -f /usr/local/bin/kubertsec
    sudo rm -f /etc/systemd/system/kubertsec.service
    echo "KubeRTSec uninstalled"
    ;;
  help|*)
    echo ""
    echo "  KubeRTSec CLI v1.0.0"
    echo ""
    echo "  Usage: kubertsec <command>"
    echo ""
    echo "  Commands:"
    echo "    start       Start KubeRTSec (dashboard + controller)"
    echo "    stop        Stop KubeRTSec"
    echo "    agent       Start eBPF agent (needs sudo)"
    echo "    status      Check health + K8s pods"
    echo "    logs        Stream docker compose logs"
    echo "    dashboard   Open dashboard in browser"
    echo "    pf-start    Restart port-forwards (prometheus + grafana)"
    echo "    uninstall   Remove KubeRTSec completely"
    echo ""
    ;;
esac
CLISCRIPT

sudo chmod +x /usr/local/bin/kubertsec
success "kubertsec CLI installed → /usr/local/bin/kubertsec"

# ════════════════════════════════════════════════════════════════
# Systemd service for auto-start on boot
# ════════════════════════════════════════════════════════════════

if command -v systemctl &>/dev/null; then
  sudo tee /etc/systemd/system/kubertsec.service > /dev/null << SVCEOF
[Unit]
Description=KubeRTSec Runtime Security Platform
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=${USER}
WorkingDirectory=${INSTALL_DIR}
ExecStartPre=-/usr/bin/kubectl port-forward svc/prometheus-svc -n monitoring 9090:9090
ExecStartPre=-/usr/bin/kubectl port-forward svc/grafana-svc    -n monitoring 3001:3000
ExecStart=/usr/local/bin/docker compose up -d
ExecStop=/usr/local/bin/docker compose down
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

  sudo systemctl daemon-reload
  sudo systemctl enable kubertsec.service &>/dev/null && \
    success "Systemd service enabled (auto-start on boot)" || \
    warn "Could not enable systemd service"
fi

# ════════════════════════════════════════════════════════════════
# Final verification
# ════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║         KubeRTSec Installation Complete! 🎉              ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check what's actually running
CTRL_OK=false; DASH_OK=false; PROM_OK=false; GRAF_OK=false
curl -sf http://localhost:8080/healthz &>/dev/null && CTRL_OK=true
curl -sf http://localhost:3000/         &>/dev/null && DASH_OK=true
curl -sf http://localhost:9090/-/healthy &>/dev/null && PROM_OK=true
curl -sf http://localhost:3001/api/health &>/dev/null && GRAF_OK=true

echo -e "  ${BOLD}Service Status:${NC}"
$CTRL_OK && echo -e "  ${GREEN}✓${NC} Controller   → ${CYAN}http://localhost:8080${NC}" || \
            echo -e "  ${YELLOW}⚠${NC} Controller   → starting..."
$DASH_OK && echo -e "  ${GREEN}✓${NC} Dashboard    → ${CYAN}http://localhost:3000${NC}" || \
            echo -e "  ${YELLOW}⚠${NC} Dashboard    → starting..."
$PROM_OK && echo -e "  ${GREEN}✓${NC} Prometheus   → ${CYAN}http://localhost:9090${NC}" || \
            echo -e "  ${YELLOW}⚠${NC} Prometheus   → starting..."
$GRAF_OK && echo -e "  ${GREEN}✓${NC} Grafana      → ${CYAN}http://localhost:3001${NC}  (admin / ${GRAFANA_PASS:-admin123})" || \
            echo -e "  ${YELLOW}⚠${NC} Grafana      → starting..."

echo ""
echo -e "  ${BOLD}Quick Commands:${NC}"
echo -e "  ${CYAN}kubertsec start${NC}      — start everything"
echo -e "  ${CYAN}kubertsec agent${NC}      — start eBPF agent (kernel-level detection)"
echo -e "  ${CYAN}kubertsec status${NC}     — check health"
echo -e "  ${CYAN}kubertsec logs${NC}       — view live logs"
echo -e "  ${CYAN}kubertsec dashboard${NC}  — open browser"
echo -e "  ${CYAN}kubertsec stop${NC}       — stop everything"
echo -e "  ${CYAN}kubertsec uninstall${NC}  — remove completely"
echo ""
echo -e "  ${BOLD}Start eBPF Agent (for real kernel-level detection):${NC}"
echo -e "  ${CYAN}kubertsec agent${NC}"
echo ""
echo -e "  ${BOLD}Test attack detection:${NC}"
echo -e "  ${CYAN}kubectl exec -it attacker -- bash${NC}  (if attacker pod exists)"
echo -e "  ${CYAN}kubectl run attacker --image=ubuntu:22.04 --restart=Never -- sleep 3600${NC}"
echo ""
echo -e "  ${YELLOW}Note:${NC} If port-forwards are lost after reboot, run: ${CYAN}kubertsec pf-start${NC}"
echo ""
