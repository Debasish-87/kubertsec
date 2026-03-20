// utils/export.js
// Data export: CSV, JSON, PDF text report

import { format } from 'date-fns';

/* ──────────────────────────────────────────
   1. JSON Export
────────────────────────────────────────── */
export function exportJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: 'application/json',
  });
  triggerDownload(blob, filename || `kubertsec-export-${ts()}.json`);
}

/* ──────────────────────────────────────────
   2. CSV Export (alerts)
────────────────────────────────────────── */
export function exportAlertsCSV(alerts) {
  const headers = [
    'Timestamp',
    'Severity',
    'Namespace',
    'Pod',
    'Process',
    'Rule',
    'Action',
    'Message',
  ];

  const rows = alerts.map((a) => [
    safeCSV(fmtTime(a.timestamp)),
    safeCSV(a.severity?.toUpperCase()),
    safeCSV(a.namespace),
    safeCSV(a.pod),
    safeCSV(a.process),
    safeCSV(a.rule),
    safeCSV(a.action),
    safeCSV(a.message),
  ]);

  const csv = [headers, ...rows].map((r) => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  triggerDownload(blob, `kubertsec-alerts-${ts()}.csv`);
}

/* ──────────────────────────────────────────
   3. CSV Export (pods)
────────────────────────────────────────── */
export function exportPodsCSV(pods) {
  const headers = [
    'Pod Name',
    'Namespace',
    'Status',
    'Threats',
    'Processes Seen',
    'Last Event',
  ];

  const rows = Object.values(pods).map((p) => [
    safeCSV(p.name),
    safeCSV(p.namespace),
    safeCSV(p.status),
    p.threats,
    safeCSV((p.processes || []).join(' | ')),
    safeCSV(p.lastEvent),
  ]);

  const csv = [headers, ...rows].map((r) => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  triggerDownload(blob, `kubertsec-pods-${ts()}.csv`);
}

/* ──────────────────────────────────────────
   4. Full Security Report (HTML → printable)
────────────────────────────────────────── */
export function exportSecurityReport(state) {
  const { alerts, pods, stats } = state;
  const critCount = alerts.filter((a) => a.severity === 'critical').length;
  // const highCount = alerts.filter((a) => a.severity === 'high').length;
  const blockedProcs = alerts.filter(
    (a) => a.action === 'killed' || a.action === 'kill'
  );
  const podList = Object.values(pods);
  const compromisedPods = podList.filter((p) => p.threats > 0);
  const now = new Date();

  const reportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>KubeRTSec Security Report — ${fmtTime(now)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Courier New', monospace; background: #fff; color: #111; padding: 40px; max-width: 900px; margin: auto; }
  h1 { font-size: 24px; font-weight: 700; border-bottom: 3px solid #111; padding-bottom: 10px; margin-bottom: 24px; }
  h2 { font-size: 16px; font-weight: 700; margin: 28px 0 10px; text-transform: uppercase; letter-spacing: 1px; border-left: 4px solid #111; padding-left: 10px; }
  .meta { font-size: 12px; color: #555; margin-bottom: 24px; }
  .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
  .stat-box { border: 1px solid #ccc; padding: 14px; border-radius: 4px; }
  .stat-num { font-size: 28px; font-weight: 700; }
  .stat-lbl { font-size: 11px; color: #777; text-transform: uppercase; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 11px; margin-bottom: 16px; }
  th { background: #111; color: #fff; padding: 6px 8px; text-align: left; }
  td { padding: 6px 8px; border-bottom: 1px solid #eee; }
  tr:nth-child(even) td { background: #f9f9f9; }
  .tag-critical { background: #fee; color: #c00; padding: 1px 6px; border-radius: 3px; font-weight: 700; }
  .tag-high { background: #fff3e0; color: #e65100; padding: 1px 6px; border-radius: 3px; font-weight: 700; }
  .tag-medium { background: #fffde7; color: #f57f17; padding: 1px 6px; border-radius: 3px; }
  .tag-low { background: #e3f2fd; color: #1565c0; padding: 1px 6px; border-radius: 3px; }
  .footer { margin-top: 40px; font-size: 11px; color: #aaa; border-top: 1px solid #eee; padding-top: 12px; }
  @media print { body { padding: 20px; } }
</style>
</head>
<body>
<h1>🛡 KubeRTSec Security Report</h1>
<div class="meta">
  Generated: ${format(now, 'PPpp')} &nbsp;|&nbsp;
  Cluster: prod-cluster-01 &nbsp;|&nbsp;
  Total Alerts: ${alerts.length}
</div>

<h2>Executive Summary</h2>
<div class="stat-grid">
  <div class="stat-box"><div class="stat-num" style="color:#c00">${stats.threats || alerts.length}</div><div class="stat-lbl">Total Threats</div></div>
  <div class="stat-box"><div class="stat-num" style="color:#e65100">${critCount}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat-box"><div class="stat-num" style="color:#1565c0">${podList.length}</div><div class="stat-lbl">Pods Monitored</div></div>
  <div class="stat-box"><div class="stat-num" style="color:#2e7d32">${blockedProcs.length}</div><div class="stat-lbl">Processes Killed</div></div>
</div>

<h2>Compromised Pods (${compromisedPods.length})</h2>
<table>
  <thead><tr><th>Pod</th><th>Namespace</th><th>Threats</th><th>Suspicious Processes</th><th>Last Event</th></tr></thead>
  <tbody>
    ${compromisedPods.length === 0
      ? '<tr><td colspan="5">No compromised pods</td></tr>'
      : compromisedPods
        .map(
          (p) => `<tr>
      <td>${p.name}</td><td>${p.namespace}</td>
      <td style="font-weight:700;color:#c00">${p.threats}</td>
      <td>${(p.processes || []).join(', ')}</td>
      <td>${p.lastEvent || '—'}</td>
    </tr>`
        )
        .join('')}
  </tbody>
</table>

<h2>Alert Log (Last ${Math.min(alerts.length, 100)})</h2>
<table>
  <thead><tr><th>Time</th><th>Severity</th><th>Namespace</th><th>Pod</th><th>Process</th><th>Rule</th><th>Action</th></tr></thead>
  <tbody>
    ${alerts.slice(0, 100).map((a) => `<tr>
      <td>${fmtTime(a.timestamp)}</td>
      <td><span class="tag-${a.severity}">${(a.severity || '').toUpperCase()}</span></td>
      <td>${a.namespace}</td><td>${a.pod}</td>
      <td><code>${a.process}</code></td>
      <td>${a.rule}</td><td>${a.action}</td>
    </tr>`).join('')}
  </tbody>
</table>

<h2>Blocked Processes (${blockedProcs.length})</h2>
<table>
  <thead><tr><th>Time</th><th>Pod</th><th>Process</th><th>Rule</th></tr></thead>
  <tbody>
    ${blockedProcs.length === 0
      ? '<tr><td colspan="4">No processes killed</td></tr>'
      : blockedProcs
        .map(
          (a) => `<tr>
      <td>${fmtTime(a.timestamp)}</td>
      <td>${a.pod}</td>
      <td><code>${a.process}</code></td>
      <td>${a.rule}</td>
    </tr>`
        )
        .join('')}
  </tbody>
</table>

<div class="footer">
  KubeRTSec Runtime Security Platform &nbsp;|&nbsp; Report generated ${format(now, 'PPpp')} &nbsp;|&nbsp; Confidential
</div>
</body>
</html>`;

  const blob = new Blob([reportHTML], { type: 'text/html;charset=utf-8;' });
  triggerDownload(blob, `kubertsec-report-${ts()}.html`);
}

/* ──────────────────────────────────────────
   5. Timeline Export (JSON)
────────────────────────────────────────── */
export function exportTimeline(alerts) {
  const timeline = alerts.map((a) => ({
    timestamp: a.timestamp,
    event: a.message,
    pod: a.pod,
    namespace: a.namespace,
    process: a.process,
    rule: a.rule,
    severity: a.severity,
    action: a.action,
  }));
  exportJSON({ generated: new Date().toISOString(), timeline }, `kubertsec-timeline-${ts()}.json`);
}

/* ──────────────────────────────────────────
   Helpers
────────────────────────────────────────── */
function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function safeCSV(val) {
  if (val === undefined || val === null) return '""';
  const s = String(val).replace(/"/g, '""');
  return `"${s}"`;
}

function fmtTime(ts) {
  try {
    return format(new Date(ts), 'yyyy-MM-dd HH:mm:ss');
  } catch {
    return String(ts || '');
  }
}

function ts() {
  return format(new Date(), 'yyyyMMdd-HHmmss');
}
