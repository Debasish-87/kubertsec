#!/usr/bin/env bash
# ============================================================
#  KubeRTSec — Uninstaller
#  Usage: bash uninstall.sh [OPTIONS]
#  Options:
#    --namespace <ns>   Namespace to remove (default: kubertsec)
#    --keep-monitoring  Keep Prometheus + Grafana
#    --force            Skip confirmation prompt
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[✓]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
step()    { echo -e "\n${BOLD}${RED}━━━ $* ━━━${NC}"; }

# ── Defaults ──────────────────────────────────────────────────
NAMESPACE="kubertsec"
KEEP_MONITORING=false
FORCE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --namespace)       NAMESPACE="$2"; shift 2 ;;
    --keep-monitoring) KEEP_MONITORING=true; shift ;;
    --force)           FORCE=true; shift ;;
    -h|--help)
      echo "Usage: $0 [--namespace <ns>] [--keep-monitoring] [--force]"
      exit 0 ;;
    *) shift ;;
  esac
done

echo -e "${RED}${BOLD}"
cat << 'BANNER'
██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ████████╗███████╗███████╗ ██████╗
██║ ██╔╝██║   ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔════╝
█████╔╝ ██║   ██║██████╔╝█████╗  ██████╔╝   ██║   ███████╗█████╗  ██║
██╔═██╗ ██║   ██║██╔══██╗██╔══╝  ██╔══██╗   ██║   ╚════██║██╔══╝  ██║
██║  ██╗╚██████╔╝██████╔╝███████╗██║  ██║   ██║   ███████║███████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝
                            Uninstaller
BANNER
echo -e "${NC}"

# ── Confirm ───────────────────────────────────────────────────
if [[ "$FORCE" == "false" ]]; then
  echo -e "${YELLOW}This will remove KubeRTSec from namespace '${NAMESPACE}'.${NC}"
  if [[ "$KEEP_MONITORING" == "false" ]]; then
    echo -e "${YELLOW}Prometheus and Grafana in 'monitoring' will also be removed.${NC}"
  fi
  echo ""
  read -r -p "Are you sure? (y/N): " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
fi

# ── Stop port-forwards ────────────────────────────────────────
step "Stopping Port Forwards"
pkill -f "port-forward.*prometheus-svc" 2>/dev/null && success "Stopped prometheus port-forward" || true
pkill -f "port-forward.*grafana-svc"    2>/dev/null && success "Stopped grafana port-forward"    || true
fuser -k 9090/tcp &>/dev/null 2>&1 && success "Freed port 9090" || true
fuser -k 3001/tcp &>/dev/null 2>&1 && success "Freed port 3001" || true
fuser -k 8080/tcp &>/dev/null 2>&1 && success "Freed port 8080" || true

# ── Remove KubeRTSec namespace ───────────────────────────────
step "Removing KubeRTSec (namespace: ${NAMESPACE})"
if kubectl get namespace "$NAMESPACE" &>/dev/null 2>&1; then
  kubectl delete namespace "$NAMESPACE" --timeout=60s
  success "Namespace '${NAMESPACE}' deleted"
else
  info "Namespace '${NAMESPACE}' not found — skipping"
fi

# ── Remove RBAC ───────────────────────────────────────────────
step "Removing RBAC"
kubectl delete clusterrole        kubertsec-controller    &>/dev/null 2>&1 && success "ClusterRole removed"        || true
kubectl delete clusterrolebinding kubertsec-controller    &>/dev/null 2>&1 && success "ClusterRoleBinding removed"  || true
kubectl delete clusterrole        kubertsec-prometheus    &>/dev/null 2>&1 && success "Prometheus ClusterRole removed"        || true
kubectl delete clusterrolebinding kubertsec-prometheus    &>/dev/null 2>&1 && success "Prometheus ClusterRoleBinding removed"  || true

# ── Remove Prometheus + Grafana ───────────────────────────────
if [[ "$KEEP_MONITORING" == "false" ]]; then
  step "Removing Prometheus & Grafana"

  for res in \
    deployment/prometheus \
    deployment/grafana \
    service/prometheus-svc \
    service/grafana-svc \
    configmap/prometheus-config \
    configmap/grafana-datasource \
    serviceaccount/prometheus-sa; do
    kubectl delete "$res" -n monitoring &>/dev/null 2>&1 \
      && success "Deleted: $res" || true
  done

  # Remove monitoring namespace if nothing else is running
  REMAINING=$(kubectl get all -n monitoring 2>/dev/null \
    | grep -v "^NAME" | grep -v "^$" | wc -l || echo "0")

  if [[ "$REMAINING" -eq 0 ]]; then
    kubectl delete namespace monitoring &>/dev/null 2>&1 \
      && success "Namespace 'monitoring' deleted" || true
  else
    info "Other resources still in 'monitoring' — namespace kept"
  fi
else
  info "Skipping monitoring stack (--keep-monitoring)"
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  KubeRTSec Uninstalled Successfully ✓  ║${NC}"
echo -e "${GREEN}${BOLD}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "To reinstall:  ${BOLD}bash setup.sh${NC}"
echo -e "               ${BOLD}make install${NC}"
echo ""