# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| main branch | Yes |
| older commits | No |

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

### Option 1 — GitHub Private Security Advisory (recommended)

Go to: https://github.com/Debasish-87/kubertsec/security/advisories/new

This is encrypted, private, and the preferred method.

### Option 2 — Email

Send details to: `your-email@example.com`

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Affected component (eBPF agent, controller, frontend, rules)
- Impact assessment
- Suggested fix (if any)

**Response target:** 48 hours acknowledgement, 7 days for initial assessment.

---

## Known Limitations (Not Vulnerabilities)

These are known design constraints, not security bugs:

- eBPF agent requires `root` or `CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE` — this is expected for kernel-level monitoring
- `read_args()` captures only `argv[0..2]` — longer argument lists may have incomplete context
- `pkg/posture/` is not yet implemented — no static posture checks
- Network monitoring uses `tcp_v4_connect` only — IPv6 connections are not monitored
- Behavioral chain window is 60 seconds — very slow multi-step attacks may evade correlation
- The tool is designed for threat **detection**, not prevention — it kills processes after detection, not before execution

---

## Scope

In scope for vulnerability reports:
- False negatives in critical detection rules that could allow serious attacks to go undetected
- Privilege escalation in the controller or agent itself
- Information disclosure in the API (unauthenticated sensitive data)
- Denial of service in the ring buffer or event processing pipeline

Out of scope:
- Known limitations listed above
- Attacks requiring physical access to the node
- Attacks requiring compromised Kubernetes control plane
