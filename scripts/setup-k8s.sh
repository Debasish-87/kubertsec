#!/bin/bash
# scripts/setup-k8s.sh — Connect KubeRTSec to your real Kubernetes cluster
# Run once before: make dev
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║  KubeRTSec — K8s Setup                   ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Check kubectl ──────────────────────────────────────────────────────────
if ! command -v kubectl &>/dev/null; then
  echo -e "${RED}✗ kubectl not found. Install it first.${NC}"
  exit 1
fi

# ── 2. Check cluster is reachable ─────────────────────────────────────────────
echo -e "${CYAN}► Checking cluster connection...${NC}"
if ! kubectl cluster-info &>/dev/null; then
  echo -e "${RED}✗ Cannot connect to Kubernetes cluster.${NC}"
  echo "  Make sure your cluster is running: kind get clusters"
  exit 1
fi
CONTEXT=$(kubectl config current-context)
echo -e "${GREEN}✓ Connected to: ${CONTEXT}${NC}"

# ── 3. Generate Docker-compatible kubeconfig ──────────────────────────────────
# With network_mode: host, controller uses 127.0.0.1 directly — no modification needed
echo -e "${GREEN}✓ Using real kubeconfig: ~/.kube/config${NC}"
echo -e "  (controller runs on host network — no translation needed)"

# ── 4. Port-forward Prometheus ────────────────────────────────────────────────
echo -e "${CYAN}► Setting up Prometheus port-forward...${NC}"
pkill -f "port-forward.*prometheus" 2>/dev/null || true
sleep 1

# Try to find prometheus service
PROM_NS=""
for ns in monitoring default kube-prometheus-stack; do
  if kubectl get svc -n "$ns" 2>/dev/null | grep -qi "prometheus"; then
    PROM_NS="$ns"
    break
  fi
done

if [ -n "$PROM_NS" ]; then
  PROM_SVC=$(kubectl get svc -n "$PROM_NS" 2>/dev/null \
    | grep -i prometheus | grep -v alertmanager | grep -v pushgateway \
    | head -1 | awk '{print $1}')
  if [ -n "$PROM_SVC" ]; then
    kubectl port-forward "svc/${PROM_SVC}" -n "$PROM_NS" 9090:9090 \
      >/tmp/pf-prometheus.log 2>&1 &
    sleep 2
    if curl -sf http://localhost:9090/-/healthy >/dev/null 2>&1; then
      echo -e "${GREEN}✓ Prometheus → http://localhost:9090${NC}"
      echo "  (svc/${PROM_SVC} in namespace ${PROM_NS})"
    else
      echo -e "${YELLOW}⚠ Prometheus port-forward started but not responding yet${NC}"
      echo "  Check: cat /tmp/pf-prometheus.log"
    fi
  else
    echo -e "${YELLOW}⚠ No Prometheus service found in namespace: ${PROM_NS}${NC}"
  fi
else
  echo -e "${YELLOW}⚠ Prometheus not found in cluster. Metrics page will show 'Prometheus ✗'${NC}"
  echo "  Install with: kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/kube-prometheus/main/manifests/setup/"
fi

# ── 5. Port-forward Grafana ───────────────────────────────────────────────────
echo -e "${CYAN}► Setting up Grafana port-forward...${NC}"
pkill -f "port-forward.*grafana" 2>/dev/null || true
sleep 1

GRAF_NS=""
for ns in monitoring default grafana kube-prometheus-stack; do
  if kubectl get svc -n "$ns" 2>/dev/null | grep -qi "grafana"; then
    GRAF_NS="$ns"
    break
  fi
done

if [ -n "$GRAF_NS" ]; then
  GRAF_SVC=$(kubectl get svc -n "$GRAF_NS" 2>/dev/null \
    | grep -i grafana | head -1 | awk '{print $1}')
  if [ -n "$GRAF_SVC" ]; then
    kubectl port-forward "svc/${GRAF_SVC}" -n "$GRAF_NS" 3001:3000 \
      >/tmp/pf-grafana.log 2>&1 &
    sleep 2
    if curl -sf http://localhost:3001/api/health >/dev/null 2>&1; then
      echo -e "${GREEN}✓ Grafana    → http://localhost:3001${NC}"
      echo "  (svc/${GRAF_SVC} in namespace ${GRAF_NS})"
    else
      echo -e "${YELLOW}⚠ Grafana port-forward started but not responding yet${NC}"
      echo "  Check: cat /tmp/pf-grafana.log"
    fi
  fi
else
  echo -e "${YELLOW}⚠ Grafana not found in cluster. Grafana panel will show 'OFFLINE'${NC}"
fi

# ── 6. Show pod summary ───────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}► Current cluster pods:${NC}"
kubectl get pods -A --no-headers 2>/dev/null \
  | awk '{printf "  %-40s %-20s %s\n", $2, $1, $4}' \
  | head -20
TOTAL=$(kubectl get pods -A --no-headers 2>/dev/null | wc -l)
echo -e "  ... ${TOTAL} total pods"

# ── 7. Done ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup complete! Now run: make dev            ${NC}"
echo -e "${GREEN}  Dashboard → http://localhost:3000            ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""
echo -e "  Ports active:"
echo -e "  • KubeRTSec Controller → ${CYAN}http://localhost:8080${NC}"
echo -e "  • KubeRTSec Dashboard  → ${CYAN}http://localhost:3000${NC}"
echo -e "  • Prometheus           → ${CYAN}http://localhost:9090${NC}"
echo -e "  • Grafana              → ${CYAN}http://localhost:3001${NC}"
echo ""
