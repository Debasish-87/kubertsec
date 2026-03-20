#!/usr/bin/env bash
# ============================================================
#  KubeRTSec — Open Source Setup Script
#  Run this from your repo root:  bash add_opensource_files.sh
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${CYAN}[→]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BOLD}KubeRTSec — Adding open source files${NC}"
echo ""

# ── Create directories ───────────────────────────────────────
info "Creating .github directories..."
mkdir -p .github/ISSUE_TEMPLATE
mkdir -p .github/workflows
ok "Directories created"

# ── Copy files ───────────────────────────────────────────────

info "Copying CONTRIBUTING.md..."
cp "$SCRIPT_DIR/CONTRIBUTING.md" ./CONTRIBUTING.md
ok "CONTRIBUTING.md"

info "Copying CODE_OF_CONDUCT.md..."
cp "$SCRIPT_DIR/CODE_OF_CONDUCT.md" ./CODE_OF_CONDUCT.md
ok "CODE_OF_CONDUCT.md"

info "Copying SECURITY.md..."
cp "$SCRIPT_DIR/SECURITY.md" ./SECURITY.md
ok "SECURITY.md"

info "Copying .gitattributes..."
cp "$SCRIPT_DIR/.gitattributes" ./.gitattributes
ok ".gitattributes"

info "Copying GitHub Issue Templates..."
cp "$SCRIPT_DIR/.github/ISSUE_TEMPLATE/bug_report.yml"       .github/ISSUE_TEMPLATE/bug_report.yml
cp "$SCRIPT_DIR/.github/ISSUE_TEMPLATE/feature_request.yml"  .github/ISSUE_TEMPLATE/feature_request.yml
cp "$SCRIPT_DIR/.github/ISSUE_TEMPLATE/detection_rule.yml"   .github/ISSUE_TEMPLATE/detection_rule.yml
ok "Issue templates"

info "Copying PR template..."
cp "$SCRIPT_DIR/.github/PULL_REQUEST_TEMPLATE.md" .github/PULL_REQUEST_TEMPLATE.md
ok "PR template"

info "Copying GitHub Actions CI..."
cp "$SCRIPT_DIR/.github/workflows/ci.yml" .github/workflows/ci.yml
ok "CI workflow"

# ── Git commit ───────────────────────────────────────────────
echo ""
info "Staging all files..."
git add \
  CONTRIBUTING.md \
  CODE_OF_CONDUCT.md \
  SECURITY.md \
  .gitattributes \
  .github/ISSUE_TEMPLATE/bug_report.yml \
  .github/ISSUE_TEMPLATE/feature_request.yml \
  .github/ISSUE_TEMPLATE/detection_rule.yml \
  .github/PULL_REQUEST_TEMPLATE.md \
  .github/workflows/ci.yml

info "Committing..."
git commit -m "chore: add open source community files

- CONTRIBUTING.md with full dev guide
- CODE_OF_CONDUCT.md (Contributor Covenant)
- SECURITY.md with private disclosure process
- .gitattributes to fix Go/C language stats
- GitHub Issue Templates (bug, feature, detection rule)
- GitHub PR Template
- GitHub Actions CI (Go build + React build + YAML lint)"

info "Pushing..."
git push

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║   Open source setup complete!               ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Next steps:"
echo -e "  ${CYAN}1.${NC} Go to GitHub repo → Settings → About"
echo -e "     Add topics: ebpf kubernetes runtime-security security golang react"
echo -e "     Add website: https://kubertsec.vercel.app"
echo ""
echo -e "  ${CYAN}2.${NC} Update SECURITY.md with your real email"
echo -e "     Or use GitHub Security Advisories (recommended)"
echo ""
echo -e "  ${CYAN}3.${NC} Turn on Discussions:"
echo -e "     Settings → Features → Discussions → Enable"
echo ""
