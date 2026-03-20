# Security Policy

KubeRTSec is a security-critical project — it runs with elevated kernel privileges and monitors production workloads. We take vulnerability reports seriously and commit to responding promptly and transparently.

---

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [What to Include](#what-to-include)
- [Our Response Commitments](#our-response-commitments)
- [Disclosure Policy](#disclosure-policy)
- [Scope](#scope)
- [Known Limitations](#known-limitations)
- [Security Best Practices for Deployers](#security-best-practices-for-deployers)

---

## Supported Versions

| Version / Branch | Supported | Notes |
|------------------|-----------|-------|
| `main` | ✅ Yes | Always receives security fixes |
| Tagged releases | ✅ Yes | Latest release only |
| Older commits / forks | ❌ No | Upgrade to `main` or the latest release |

We do not backport security fixes to older tagged releases. If you are running a pinned older version, please upgrade.

---

## Reporting a Vulnerability

> **Do NOT open a public GitHub Issue for security vulnerabilities.** Public disclosure before a fix is available puts all users at risk.

### Option 1 — GitHub Private Security Advisory *(recommended)*

Use GitHub's encrypted, private advisory system:

**[Open a Private Security Advisory →](https://github.com/Debasish-87/kubertsec/security/advisories/new)**

This is the preferred method. It keeps the report private, allows secure collaboration between reporter and maintainers, and automatically creates a CVE when the issue is confirmed.

### Option 2 — Email

If you cannot use GitHub's advisory system, send details to:

**`security@kubertsec.dev`** *(replace with your actual contact address)*

Include `[SECURITY]` in the subject line.

---

## What to Include

A useful report gives us everything needed to reproduce and assess the issue. Please include as many of the following as apply:

| Field | Description |
|-------|-------------|
| **Summary** | One-sentence description of the vulnerability |
| **Component** | eBPF agent, controller, frontend, rules engine, Docker/K8s manifests |
| **Affected versions** | Commit hash, tag, or branch |
| **Severity (your assessment)** | Critical / High / Medium / Low — use [CVSS v3.1](https://www.first.org/cvss/calculator/3.1) if possible |
| **Steps to reproduce** | Minimal, numbered reproduction steps |
| **Expected vs actual behaviour** | What should happen and what does happen |
| **Impact** | What an attacker could achieve — privilege escalation, data exposure, DoS, etc. |
| **Proof of concept** | Code, commands, or screenshots demonstrating the issue |
| **Suggested fix** | Optional — any ideas on remediation are welcome |
| **Disclosure preference** | Coordinated (default) or immediate |

---

## Our Response Commitments

| Milestone | Target |
|-----------|--------|
| Acknowledgement of receipt | Within **48 hours** |
| Initial triage and severity assessment | Within **7 days** |
| Patch or mitigation for Critical / High | Within **14 days** |
| Patch or mitigation for Medium / Low | Within **30 days** |
| Public disclosure (coordinated) | After patch is released and deployers have had time to upgrade |

We will keep you informed at each stage. If you do not receive an acknowledgement within 48 hours, please follow up — your report may have been caught by a spam filter.

We credit all reporters in the release notes (unless you prefer to remain anonymous).

---

## Disclosure Policy

We follow **coordinated disclosure**:

1. Reporter submits the vulnerability privately
2. Maintainers confirm the issue and develop a fix
3. A patch is released to `main` and as a new tagged release
4. A GitHub Security Advisory (with CVE if applicable) is published
5. The reporter is credited unless anonymity is requested

We ask reporters to allow a reasonable window — typically **90 days** — before independent public disclosure. If we fail to meet our response commitments, you are free to disclose earlier and we will not object.

---

## Scope

### In Scope

We consider the following to be security vulnerabilities worth reporting:

- **False negatives in critical detection rules** — a rule that should fire for a reverse shell, crypto miner, or container escape but does not
- **Privilege escalation in the controller or agent** — an attacker gaining higher privileges than intended via a KubeRTSec component
- **Unauthenticated sensitive data exposure** — API endpoints returning alert data, pod inventory, or cluster metrics without authentication
- **Denial of service in the event pipeline** — inputs that crash the agent, exhaust the eBPF ring buffer, or cause the controller to stop processing events
- **Rule injection** — crafted input that causes a malicious rule to be loaded or an existing rule to be silently bypassed
- **Kubernetes manifest misconfigurations** — overly permissive RBAC, missing SecurityContext constraints, or NetworkPolicy gaps in the provided manifests
- **Dependency vulnerabilities with a credible exploit path** — in Go modules, npm packages, or base Docker images

### Out of Scope

These are not considered security vulnerabilities for this project:

- Attacks requiring physical access to the Kubernetes node
- Attacks requiring an already-compromised Kubernetes control plane or `cluster-admin` credentials
- Theoretical vulnerabilities with no demonstrated exploit path
- Social engineering attacks against maintainers or contributors
- Known limitations documented in the [Known Limitations](#known-limitations) section below
- Vulnerabilities in third-party tools (Prometheus, Grafana, BoltDB) — please report these upstream

---

## Known Limitations

The following are **intentional design constraints**, not security vulnerabilities. Please do not report them:

| Limitation | Detail |
|------------|--------|
| **Agent requires elevated privileges** | The eBPF agent needs `privileged: true` or `CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE` — inherent to kernel-level tracing |
| **Partial argument capture** | `read_args()` currently captures `argv[0..2]` only — longer argument lists have incomplete context in alerts |
| **Posture checks not implemented** | `pkg/posture/` is scaffolded but not yet functional |
| **IPv4 only for network monitoring** | `tcp_v4_connect` kprobe is used — IPv6 connections are not monitored |
| **60-second correlation window** | Multi-step attacks slower than 60 seconds may evade behavioral correlation |
| **Detection, not prevention** | The agent kills processes after `execve` — the syscall has already been issued. Exploits completing in a single syscall are not preventable by this design |

If you have ideas for improving any of these, please open a [GitHub Discussion](https://github.com/Debasish-87/kubertsec/discussions) or contribute a fix via a Pull Request.

---

## Security Best Practices for Deployers

If you are running KubeRTSec in production, we recommend the following hardening steps.

**Authentication & secrets**

- Enable authentication on the controller API — it ships without auth by default; add an Ingress with OAuth2 Proxy or mTLS
- Rotate `GRAFANA_PASSWORD` immediately after deployment — never use the default `admin123`
- Store all secrets in Kubernetes Secrets or a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager) — never in `.env` files committed to source control

**Network**

- Apply the included `NetworkPolicy` manifest and verify your CNI plugin enforces it
- Restrict the `/event` agent ingestion endpoint to internal cluster traffic only
- Add TLS to all external-facing endpoints via Ingress + cert-manager

**Kubernetes hardening**

- Review the DaemonSet manifest before deploying — understand the privileges the agent requires and why
- Run the controller with `readOnlyRootFilesystem: true` and as non-root (UID 1000) — both are set in the provided manifest
- Audit the `ClusterRole` granted to the controller's ServiceAccount and remove any permissions not required in your environment

**Ongoing**

- Subscribe to [GitHub Security Advisories](https://github.com/Debasish-87/kubertsec/security/advisories) for this repository to receive notifications of future disclosures
- Pin image digests in production rather than using `:latest` tags
- Run `make test` and `make attack-test` after every upgrade to confirm detections still fire correctly