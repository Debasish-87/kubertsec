// pages/Alerts.jsx — KubeRTSec Production Live Alerts
import React, { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { useApp } from '../store/AppStore';
import { SeverityBadge, NsTag, Mono, fmtTime, ExportBtn } from '../components/UI';
import { exportAlertsCSV, exportJSON } from '../utils/export';

const FILTERS = ['all', 'critical', 'high', 'medium', 'low'];
const SEV_COLORS = { critical: '#ff3b3b', high: '#ff8c42', medium: '#ffd166', low: '#4db8ff' };
const PAGE_SIZE = 100; // render in batches to avoid DOM pressure

// ── Action feedback toast (inline, not global) ────────────────────────────────

function ActionMsg({ msg }) {
  if (!msg) return null;
  const ok = msg.startsWith('✓');
  return (
    <div style={{
      padding: '5px 12px', borderRadius: 6, fontSize: 10,
      fontFamily: "'JetBrains Mono', monospace",
      background: ok ? 'rgba(6,214,160,.1)' : 'rgba(255,59,59,.1)',
      border: `1px solid ${ok ? 'rgba(6,214,160,.3)' : 'rgba(255,59,59,.3)'}`,
      color: ok ? '#06d6a0' : '#ff6b6b',
      animation: 'fadeIn .2s ease',
    }}>
      {msg}
    </div>
  );
}

// ── Expanded detail row ───────────────────────────────────────────────────────

function AlertDetail({ a }) {
  return (
    <tr>
      <td colSpan={9} style={{ padding: '0 10px 10px', background: '#07111e' }}>
        <div style={{
          background: '#07111e', border: '1px solid #1a3050',
          borderRadius: 7, padding: '12px 16px',
          fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
          animation: 'slideIn .15s ease',
        }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '10px 24px', color: '#7090b0' }}>
            <div>
              <div style={{ color: '#4d7090', marginBottom: 3, fontSize: 9, letterSpacing: '.5px' }}>MESSAGE</div>
              <div style={{ color: '#e2eaf7', lineHeight: 1.4 }}>{a.message}</div>
            </div>
            <div>
              <div style={{ color: '#4d7090', marginBottom: 3, fontSize: 9, letterSpacing: '.5px' }}>TIMESTAMP (UTC)</div>
              <div style={{ color: '#e2eaf7' }}>{new Date(a.timestamp).toUTCString()}</div>
            </div>
            <div>
              <div style={{ color: '#4d7090', marginBottom: 3, fontSize: 9, letterSpacing: '.5px' }}>NODE</div>
              <div style={{ color: '#e2eaf7' }}>{a.node || '—'}</div>
            </div>
            <div>
              <div style={{ color: '#4d7090', marginBottom: 3, fontSize: 9, letterSpacing: '.5px' }}>PID / UID</div>
              <div style={{ color: '#e2eaf7' }}>{a.pid || '—'} / {a.uid || '—'}</div>
            </div>
            <div>
              <div style={{ color: '#4d7090', marginBottom: 3, fontSize: 9, letterSpacing: '.5px' }}>IP : PORT</div>
              <div style={{ color: a.ip ? '#06d6a0' : '#e2eaf7' }}>
                {a.ip ? `${a.ip}:${a.port || '?'}` : '—'}
              </div>
            </div>
            <div>
              <div style={{ color: '#4d7090', marginBottom: 3, fontSize: 9, letterSpacing: '.5px' }}>ARGS</div>
              <div style={{ color: '#e2eaf7', wordBreak: 'break-all' }}>{a.args || '—'}</div>
            </div>
            {a.containerID && (
              <div>
                <div style={{ color: '#4d7090', marginBottom: 3, fontSize: 9, letterSpacing: '.5px' }}>CONTAINER ID</div>
                <div style={{ color: '#7c4dff' }}>{a.containerID.slice(0, 12)}</div>
              </div>
            )}
            {a.image && (
              <div>
                <div style={{ color: '#4d7090', marginBottom: 3, fontSize: 9, letterSpacing: '.5px' }}>IMAGE</div>
                <div style={{ color: '#7090b0' }}>{a.image}</div>
              </div>
            )}
          </div>

          {/* Process tree */}
          {a.processTree && a.processTree.length > 0 && (
            <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid #1a3050' }}>
              <div style={{ color: '#4d7090', marginBottom: 6, fontSize: 9, letterSpacing: '.5px' }}>PROCESS TREE</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                {a.processTree.map((p, i) => (
                  <React.Fragment key={i}>
                    <span style={{
                      color: i === a.processTree.length - 1 ? '#ff3b3b' : '#4d7090',
                      fontWeight: i === a.processTree.length - 1 ? 700 : 400,
                      background: i === a.processTree.length - 1 ? 'rgba(255,59,59,.1)' : 'transparent',
                      padding: '1px 6px', borderRadius: 3,
                    }}>
                      {p}
                    </span>
                    {i < a.processTree.length - 1 && (
                      <span style={{ color: '#2d4a60', fontSize: 12 }}>›</span>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {/* Raw alert ID */}
          <div style={{ marginTop: 10, color: '#2d4060', fontSize: 9 }}>
            ID: {a.id}
          </div>
        </div>
      </td>
    </tr>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function Alerts() {
  const { state, actions } = useApp();
  const { alerts } = state;

  const [sevFilter,  setSevFilter]  = useState('all');
  const [nsFilter,   setNsFilter]   = useState('all');
  const [podFilter,  setPodFilter]  = useState('');
  const [searchText, setSearchText] = useState('');
  const [showAcked,  setShowAcked]  = useState(false);
  const [expandedId, setExpandedId] = useState(null);
  const [busy,       setBusy]       = useState({});
  const [actionMsg,  setActionMsg]  = useState('');
  const [page,       setPage]       = useState(1);
  const searchRef = useRef(null);

  // Keyboard shortcut: / to focus search
  useEffect(() => {
    const handler = (e) => {
      if (e.key === '/' && document.activeElement !== searchRef.current) {
        e.preventDefault();
        searchRef.current?.focus();
      }
      if (e.key === 'Escape') {
        setSearchText('');
        setPodFilter('');
        searchRef.current?.blur();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // Reset pagination when filters change
  useEffect(() => { setPage(1); }, [sevFilter, nsFilter, podFilter, searchText, showAcked]);

  // Flash action message
  const flash = useCallback((msg) => {
    setActionMsg(msg);
    setTimeout(() => setActionMsg(''), 3000);
  }, []);

  const namespaces = useMemo(
    () => ['all', ...Array.from(new Set(alerts.map(a => a.namespace).filter(Boolean))).sort()],
    [alerts]
  );

  const filtered = useMemo(() => {
    const search = searchText.toLowerCase();
    return alerts.filter(a => {
      if (!showAcked && a.acknowledged) return false;
      if (sevFilter !== 'all' && a.severity !== sevFilter) return false;
      if (nsFilter  !== 'all' && a.namespace !== nsFilter)  return false;
      if (podFilter && !a.pod.toLowerCase().includes(podFilter.toLowerCase())) return false;
      if (search && !(
        a.message.toLowerCase().includes(search) ||
        a.pod.toLowerCase().includes(search)     ||
        a.process.toLowerCase().includes(search) ||
        a.rule.toLowerCase().includes(search)    ||
        a.namespace.toLowerCase().includes(search)
      )) return false;
      return true;
    });
  }, [alerts, sevFilter, nsFilter, podFilter, searchText, showAcked]);

  const visible = filtered.slice(0, page * PAGE_SIZE);
  const hasMore = filtered.length > visible.length;

  // ── Actions ────────────────────────────────────────────────────────────────

  const doAck = useCallback(async (e, id) => {
    e.stopPropagation();
    setBusy(b => ({ ...b, [id]: 'ack' }));
    const res = await actions.acknowledgeAlert(id);
    setBusy(b => { const n = { ...b }; delete n[id]; return n; });
    flash(res.ok ? '✓ Alert acknowledged' : `✗ ${res.error?.message || 'Acknowledge failed'}`);
  }, [actions, flash]);

  const doDel = useCallback(async (e, id) => {
    e.stopPropagation();
    setBusy(b => ({ ...b, [id]: 'del' }));
    const res = await actions.deleteAlert(id);
    setBusy(b => { const n = { ...b }; delete n[id]; return n; });
    if (expandedId === id) setExpandedId(null);
    flash(res.ok ? '✓ Alert deleted' : `✗ ${res.error?.message || 'Delete failed'}`);
  }, [actions, expandedId, flash]);

  // ── Styles ─────────────────────────────────────────────────────────────────

  const fBtn = (f) => ({
    padding: '5px 10px', borderRadius: 6, fontSize: 10, cursor: 'pointer',
    fontFamily: "'JetBrains Mono', monospace",
    border:     `1px solid ${sevFilter === f ? (SEV_COLORS[f] || '#00e5ff') : '#1a3050'}`,
    background: sevFilter === f ? `${(SEV_COLORS[f] || '#00e5ff')}18` : 'transparent',
    color:      sevFilter === f ? (SEV_COLORS[f] || '#00e5ff') : '#4d7090',
    transition: 'all .15s',
  });

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: '12px 20px', gap: 8, overflow: 'hidden' }}>

      {/* Toolbar row 1: severity + ns + pod filters */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0, flexWrap: 'wrap' }}>
        {/* Severity filters */}
        <div style={{ display: 'flex', gap: 4 }}>
          {FILTERS.map(f => (
            <button key={f} onClick={() => setSevFilter(f)} style={fBtn(f)}>
              {f.toUpperCase()}
              {f !== 'all' && (
                <span style={{ marginLeft: 4, opacity: .6 }}>
                  {alerts.filter(a => a.severity === f).length}
                </span>
              )}
            </button>
          ))}
        </div>

        <div style={{ width: 1, height: 18, background: '#1a3050', flexShrink: 0 }} />

        {/* Namespace */}
        <select value={nsFilter} onChange={e => setNsFilter(e.target.value)} style={{
          background: '#0d1b2e', border: '1px solid #1a3050', color: '#7090b0',
          padding: '4px 8px', borderRadius: 6, fontSize: 10,
          fontFamily: "'JetBrains Mono', monospace", cursor: 'pointer',
        }}>
          {namespaces.map(ns => <option key={ns} value={ns}>{ns === 'all' ? 'All Namespaces' : ns}</option>)}
        </select>

        {/* Pod filter */}
        <input
          placeholder="filter pod…"
          value={podFilter}
          onChange={e => setPodFilter(e.target.value)}
          style={{
            background: '#0d1b2e', border: '1px solid #1a3050', color: '#e2eaf7',
            padding: '4px 10px', borderRadius: 6, fontSize: 10,
            fontFamily: "'JetBrains Mono', monospace", outline: 'none', width: 130,
          }}
        />

        {/* Show/hide acknowledged */}
        <button
          onClick={() => setShowAcked(v => !v)}
          style={{
            padding: '5px 10px', borderRadius: 6, fontSize: 10, cursor: 'pointer',
            fontFamily: "'JetBrains Mono', monospace",
            border:     `1px solid ${showAcked ? '#06d6a0' : '#1a3050'}`,
            background: showAcked ? 'rgba(6,214,160,.1)' : 'transparent',
            color:      showAcked ? '#06d6a0' : '#4d7090',
          }}
        >
          {showAcked ? 'HIDE ACKED' : 'SHOW ACKED'}
        </button>
      </div>

      {/* Toolbar row 2: search + counts + exports */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0, flexWrap: 'wrap' }}>
        {/* Full-text search */}
        <div style={{ position: 'relative', flex: '0 0 240px' }}>
          <svg viewBox="0 0 24 24" fill="none" stroke="#4d7090" strokeWidth="2" width="12" height="12"
            style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }}>
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
          </svg>
          <input
            ref={searchRef}
            placeholder="search message / pod / process…  (/)"
            value={searchText}
            onChange={e => setSearchText(e.target.value)}
            style={{
              width: '100%', background: '#0d1b2e', border: '1px solid #1a3050',
              color: '#e2eaf7', padding: '4px 10px 4px 26px',
              borderRadius: 6, fontSize: 10,
              fontFamily: "'JetBrains Mono', monospace", outline: 'none',
            }}
            onFocus={e => e.target.style.borderColor = '#00e5ff'}
            onBlur={e => e.target.style.borderColor = '#1a3050'}
          />
        </div>

        <Mono color="#4d7090">
          {filtered.length !== alerts.length
            ? `${filtered.length} / ${alerts.length} alerts`
            : `${alerts.length} alerts`}
        </Mono>

        {/* Action feedback */}
        <ActionMsg msg={actionMsg} />

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          <ExportBtn label="CSV"   icon="⬇"  onClick={() => exportAlertsCSV(filtered)} />
          <ExportBtn label="JSON"  icon="{}" onClick={() => exportJSON({ alerts: filtered, total: filtered.length, exported: new Date().toISOString() }, 'kubertsec-alerts.json')} />
          <button onClick={actions.clearAlerts} style={{
            padding: '5px 10px', borderRadius: 6, fontSize: 10, cursor: 'pointer',
            fontFamily: "'JetBrains Mono', monospace",
            background: 'rgba(255,59,59,.08)', border: '1px solid rgba(255,59,59,.25)', color: '#ff6b6b',
          }}>
            Clear
          </button>
        </div>
      </div>

      {/* Table */}
      <div style={{ flex: 1, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
        <div style={{ overflowY: 'auto', flex: 1, minHeight: 0 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
            <thead style={{ position: 'sticky', top: 0, background: '#0f1f36', zIndex: 2 }}>
              <tr>
                {['TIME', 'SEV', 'NS', 'POD', 'PROCESS', 'RULE', 'KILLED', 'ACTIONS', '▾'].map(h => (
                  <th key={h} style={{
                    padding: '8px 10px', textAlign: 'left', color: '#4d7090',
                    fontWeight: 500, borderBottom: '1px solid #1a3050',
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 9, letterSpacing: '.5px',
                    whiteSpace: 'nowrap',
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', color: '#4d7090', padding: 40, fontSize: 12 }}>
                    {alerts.length === 0
                      ? (
                        <div>
                          <div style={{ fontSize: 28, marginBottom: 10 }}>✅</div>
                          <div style={{ fontWeight: 600, color: '#06d6a0', marginBottom: 4 }}>No alerts — cluster is clean</div>
                          <div style={{ fontSize: 10, color: '#2d4060', fontFamily: "'JetBrains Mono', monospace" }}>
                            Waiting for eBPF agent events via WebSocket…
                          </div>
                        </div>
                      ) : (
                        <div>
                          <div>No alerts match current filters</div>
                          <button
                            onClick={() => { setSevFilter('all'); setNsFilter('all'); setPodFilter(''); setSearchText(''); }}
                            style={{
                              marginTop: 8, padding: '4px 12px', borderRadius: 5, fontSize: 10,
                              background: 'rgba(0,229,255,.1)', border: '1px solid rgba(0,229,255,.2)',
                              color: '#00e5ff', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace",
                            }}
                          >
                            clear filters
                          </button>
                        </div>
                      )
                    }
                  </td>
                </tr>
              ) : (
                visible.map(a => (
                  <React.Fragment key={a.id}>
                    <tr
                      onClick={() => setExpandedId(expandedId === a.id ? null : a.id)}
                      style={{
                        cursor: 'pointer',
                        opacity: a.acknowledged ? 0.45 : 1,
                        background: expandedId === a.id ? 'rgba(0,229,255,.03)' : 'transparent',
                      }}
                      onMouseEnter={e => { if (expandedId !== a.id) e.currentTarget.style.background = 'rgba(255,255,255,.02)'; }}
                      onMouseLeave={e => { if (expandedId !== a.id) e.currentTarget.style.background = 'transparent'; }}
                    >
                      <td style={{ padding: '7px 10px', borderBottom: '1px solid #0d1f33', whiteSpace: 'nowrap' }}>
                        <Mono color="#2d4a60">{fmtTime(a.timestamp)}</Mono>
                      </td>
                      <td style={{ padding: '7px 10px', borderBottom: '1px solid #0d1f33' }}>
                        <SeverityBadge severity={a.severity} />
                      </td>
                      <td style={{ padding: '7px 10px', borderBottom: '1px solid #0d1f33' }}>
                        <NsTag ns={a.namespace} />
                      </td>
                      <td style={{ padding: '7px 10px', borderBottom: '1px solid #0d1f33', maxWidth: 180 }}>
                        <Mono color="#e2eaf7" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>
                          {a.pod}
                        </Mono>
                      </td>
                      <td style={{ padding: '7px 10px', borderBottom: '1px solid #0d1f33' }}>
                        <Mono color="#00e5ff">{a.process}</Mono>
                      </td>
                      <td style={{ padding: '7px 10px', borderBottom: '1px solid #0d1f33', maxWidth: 160 }}>
                        <Mono color="#4d7090" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>
                          {a.rule}
                        </Mono>
                      </td>
                      <td style={{ padding: '7px 10px', borderBottom: '1px solid #0d1f33', textAlign: 'center' }}>
                        {a.killed
                          ? <span style={{ color: '#ff3b3b', fontSize: 9, fontFamily: "'JetBrains Mono', monospace", fontWeight: 700 }}>KILLED</span>
                          : <span style={{ color: '#1a3050', fontSize: 10 }}>—</span>
                        }
                      </td>
                      <td style={{ padding: '7px 10px', borderBottom: '1px solid #0d1f33' }}>
                        <div style={{ display: 'flex', gap: 4 }} onClick={e => e.stopPropagation()}>
                          {!a.acknowledged && (
                            <button
                              onClick={e => doAck(e, a.id)}
                              disabled={!!busy[a.id]}
                              title="Acknowledge alert"
                              style={{
                                padding: '2px 7px', borderRadius: 4, fontSize: 9, cursor: 'pointer',
                                fontFamily: "'JetBrains Mono', monospace",
                                background: 'rgba(6,214,160,.1)', border: '1px solid rgba(6,214,160,.3)', color: '#06d6a0',
                                opacity: busy[a.id] ? 0.5 : 1,
                              }}
                            >
                              {busy[a.id] === 'ack' ? '…' : 'ACK'}
                            </button>
                          )}
                          {a.acknowledged && (
                            <span style={{ color: '#06d6a0', fontSize: 9, fontFamily: "'JetBrains Mono', monospace", opacity: .6 }}>✓ acked</span>
                          )}
                          <button
                            onClick={e => doDel(e, a.id)}
                            disabled={!!busy[a.id]}
                            title="Delete alert from store"
                            style={{
                              padding: '2px 7px', borderRadius: 4, fontSize: 9, cursor: 'pointer',
                              fontFamily: "'JetBrains Mono', monospace",
                              background: 'rgba(255,59,59,.08)', border: '1px solid rgba(255,59,59,.25)', color: '#ff6b6b',
                              opacity: busy[a.id] ? 0.5 : 1,
                            }}
                          >
                            {busy[a.id] === 'del' ? '…' : 'DEL'}
                          </button>
                        </div>
                      </td>
                      <td style={{ padding: '7px 10px', borderBottom: '1px solid #0d1f33', color: '#2d4060', fontSize: 10 }}>
                        {expandedId === a.id ? '▲' : '▼'}
                      </td>
                    </tr>

                    {expandedId === a.id && <AlertDetail a={a} />}
                  </React.Fragment>
                ))
              )}
            </tbody>
          </table>

          {/* Load more */}
          {hasMore && (
            <div style={{ padding: '12px', textAlign: 'center' }}>
              <button
                onClick={() => setPage(p => p + 1)}
                style={{
                  padding: '6px 20px', borderRadius: 6, fontSize: 10,
                  background: 'rgba(0,229,255,.08)', border: '1px solid rgba(0,229,255,.2)',
                  color: '#00e5ff', cursor: 'pointer',
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                Load more ({filtered.length - visible.length} remaining)
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Footer hint */}
      <div style={{ flexShrink: 0, fontSize: 9, color: '#2d4060', fontFamily: "'JetBrains Mono', monospace", textAlign: 'right' }}>
        Press <kbd style={{ background: '#0f1f36', border: '1px solid #1a3050', padding: '1px 4px', borderRadius: 3, color: '#4d7090' }}>/</kbd> to search,{' '}
        <kbd style={{ background: '#0f1f36', border: '1px solid #1a3050', padding: '1px 4px', borderRadius: 3, color: '#4d7090' }}>Esc</kbd> to clear
      </div>
    </div>
  );
}
