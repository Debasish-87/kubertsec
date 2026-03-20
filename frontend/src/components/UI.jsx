// components/UI.jsx — Production shared components
import React from 'react';

/* ── Severity Badge ──────────────────────────────────────────── */
export const SEV_STYLES = {
  critical: { bg: '#1a0505', color: '#ff4444', border: 'rgba(255,68,68,0.35)' },
  high: { bg: '#1a0a00', color: '#ff8c42', border: 'rgba(255,140,66,0.35)' },
  medium: { bg: '#1a1500', color: '#ffd166', border: 'rgba(255,209,102,0.35)' },
  low: { bg: '#001520', color: '#4db8ff', border: 'rgba(77,184,255,0.35)' },
  info: { bg: '#001520', color: '#4db8ff', border: 'rgba(77,184,255,0.35)' },
};

export function SeverityBadge({ severity, size = 'sm' }) {
  const s = SEV_STYLES[(severity || 'info').toLowerCase()] || SEV_STYLES.info;
  const fs = size === 'sm' ? '10px' : '12px';
  const px = size === 'sm' ? '6px' : '10px';
  const py = size === 'sm' ? '2px' : '4px';
  return (
    <span style={{
      background: s.bg, color: s.color,
      border: `1px solid ${s.border}`,
      padding: `${py} ${px}`, borderRadius: 4,
      fontSize: fs, fontWeight: 700,
      fontFamily: "'JetBrains Mono', monospace",
      whiteSpace: 'nowrap', letterSpacing: '.5px',
      display: 'inline-block',
    }}>
      {(severity || 'info').toUpperCase()}
    </span>
  );
}

/* ── Status Dot — all K8s pod states ─────────────────────────── */
const STATUS_COLORS = {
  Running: '#06d6a0',
  Pending: '#ffd166',
  Terminated: '#4d7090',
  Completed: '#4d7090',
  OOMKilled: '#ff3b3b',
  CrashLoopBackOff: '#ff8c42',
  ImagePullBackOff: '#ff8c42',
  Error: '#ff3b3b',
  Failed: '#ff3b3b',
  Unknown: '#7090b0',
};

export function StatusDot({ status }) {
  const c = STATUS_COLORS[status] || '#7090b0';
  const isDead = status === 'Terminated' || status === 'Completed';
  return (
    <span style={{
      display: 'inline-block', width: 7, height: 7,
      borderRadius: '50%', background: c,
      boxShadow: isDead ? 'none' : `0 0 5px ${c}`,
      marginRight: 5, flexShrink: 0,
    }} />
  );
}

/* ── Status Badge (text) ─────────────────────────────────────── */
export function StatusBadge({ status }) {
  const c = STATUS_COLORS[status] || '#7090b0';
  const isDead = status === 'Terminated' || status === 'Completed';
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      background: `${c}12`, color: c,
      border: `1px solid ${c}30`,
      padding: '2px 8px', borderRadius: 4,
      fontSize: 10, fontFamily: "'JetBrains Mono', monospace",
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: c, boxShadow: isDead ? 'none' : `0 0 4px ${c}` }} />
      {status}
    </span>
  );
}

/* ── Action Tag ──────────────────────────────────────────────── */
export function ActionTag({ action }) {
  const isKill = action === 'killed' || action === 'kill' || action === 'Kill';
  return (
    <span style={{
      background: isKill ? 'rgba(255,68,68,.12)' : 'rgba(255,140,66,.12)',
      color: isKill ? '#ff6b6b' : '#ffac72',
      padding: '2px 8px', borderRadius: 4,
      fontSize: 10, fontFamily: "'JetBrains Mono', monospace",
      display: 'inline-block',
    }}>
      {isKill ? '✕ killed' : `⚠ ${action}`}
    </span>
  );
}

/* ── Namespace Tag ───────────────────────────────────────────── */
export function NsTag({ ns }) {
  return (
    <span style={{
      background: 'rgba(77,184,255,.08)', color: '#80ccff',
      border: '1px solid rgba(77,184,255,.2)',
      padding: '2px 7px', borderRadius: 4,
      fontSize: 9, fontFamily: "'JetBrains Mono', monospace",
      display: 'inline-block', whiteSpace: 'nowrap',
    }}>
      {ns}
    </span>
  );
}

/* ── Export Button ───────────────────────────────────────────── */
export function ExportBtn({ label, onClick, icon }) {
  return (
    <button onClick={onClick} style={{
      display: 'flex', alignItems: 'center', gap: 5,
      padding: '5px 10px', borderRadius: 6,
      background: 'transparent', border: '1px solid #1e3a5f',
      color: '#7090b0', fontSize: 10,
      fontFamily: "'Syne', sans-serif", cursor: 'pointer',
      fontWeight: 500, transition: 'all .15s', whiteSpace: 'nowrap',
    }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = '#00e5ff'; e.currentTarget.style.color = '#00e5ff'; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = '#1e3a5f'; e.currentTarget.style.color = '#7090b0'; }}
    >
      {icon && <span style={{ fontSize: 11 }}>{icon}</span>}
      {label}
    </button>
  );
}

/* ── Mono span ───────────────────────────────────────────────── */
export function Mono({ children, color, style = {} }) {
  return (
    <span style={{ fontFamily: "'JetBrains Mono', monospace", color: color || 'inherit', fontSize: 11, ...style }}>
      {children}
    </span>
  );
}

/* ── Threat Bar ──────────────────────────────────────────────── */
export function ThreatBar({ value, max = 10, color = '#ff3b3b' }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div style={{ height: 3, background: '#1a3050', borderRadius: 2, overflow: 'hidden' }}>
      <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 2, transition: 'width .5s' }} />
    </div>
  );
}

/* ── Process Tag ─────────────────────────────────────────────── */
const SUSPICIOUS_PROCS = new Set(['curl', 'wget', 'sh', 'bash', 'chmod', 'mount', 'nc', 'python', 'nmap', 'sudo', 'socat', 'nsenter', 'xmrig', 'chown']);

export function ProcTag({ proc }) {
  const isSusp = SUSPICIOUS_PROCS.has((proc || '').toLowerCase());
  return (
    <span style={{
      fontSize: 9, padding: '1px 6px', borderRadius: 3,
      fontFamily: "'JetBrains Mono', monospace",
      background: isSusp ? 'rgba(255,59,59,.1)' : 'rgba(124,77,255,.1)',
      color: isSusp ? '#ff6b6b' : '#c5a3ff',
      border: `1px solid ${isSusp ? 'rgba(255,59,59,.2)' : 'rgba(124,77,255,.2)'}`,
      display: 'inline-block',
    }}>
      {proc}
    </span>
  );
}

/* ── Panel ───────────────────────────────────────────────────── */
export function Panel({ children, style = {} }) {
  return (
    <div style={{ background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 12, padding: '20px', ...style }}>
      {children}
    </div>
  );
}

/* ── Section Header ──────────────────────────────────────────── */
export function SectionHeader({ title, right }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ width: 3, height: 14, background: '#00e5ff', borderRadius: 2 }} />
        <span style={{ fontSize: 13, fontWeight: 600, color: '#e2eaf7', letterSpacing: '.5px' }}>{title}</span>
      </div>
      {right && <div>{right}</div>}
    </div>
  );
}

/* ── Data Table ──────────────────────────────────────────────── */
export function DataTable({ children }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        {children}
      </table>
    </div>
  );
}

export function TH({ children, style = {} }) {
  return (
    <th style={{ padding: '8px 12px', textAlign: 'left', color: '#4d7090', fontWeight: 500, borderBottom: '1px solid #1a3050', fontFamily: "'JetBrains Mono', monospace", fontSize: 9, letterSpacing: '.5px', ...style }}>
      {children}
    </th>
  );
}

export function TD({ children, style = {}, colSpan }) {
  return (
    <td colSpan={colSpan} style={{ padding: '10px 12px', borderBottom: '1px solid #0d1f33', color: '#e2eaf7', ...style }}>
      {children}
    </td>
  );
}

/* ── Time helpers ────────────────────────────────────────────── */
export function fmtTime(ts) {
  try { return new Date(ts).toLocaleTimeString('en-IN', { hour12: false }); }
  catch { return String(ts || '—'); }
}

export function fmtDateTime(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleDateString('en-IN') + ' ' + d.toLocaleTimeString('en-IN', { hour12: false });
  }
  catch { return String(ts || '—'); }
}