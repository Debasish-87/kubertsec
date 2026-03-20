// pages/Pods.jsx — Production Pod Security View
// Shows ALL pods: Running, Terminated, OOMKilled, CrashLoop, Clean, Attacked
import React, { useState, useMemo } from 'react';
import { useApp } from '../store/AppStore';
import { SeverityBadge, ThreatBar, ProcTag, Mono, fmtTime, ExportBtn } from '../components/UI';
import { exportPodsCSV, exportJSON } from '../utils/export';

const STATUS_COLOR = {
  Running:          '#06d6a0',
  Pending:          '#ffd166',
  Terminated:       '#4d7090',
  Completed:        '#4d7090',
  OOMKilled:        '#ff3b3b',
  CrashLoopBackOff: '#ff8c42',
  ImagePullBackOff: '#ff8c42',
  Error:            '#ff3b3b',
  Unknown:          '#7090b0',
};

export default function Pods() {
  const { state } = useApp();
  const { pods, alerts } = state;
  const podList = Object.values(pods);

  const [selected, setSelected] = useState(null);
  const [nsFilter, setNsFilter]   = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [search, setSearch]       = useState('');

  const namespaces = useMemo(() => ['all', ...new Set(podList.map(p => p.namespace).filter(Boolean))], [podList]);
  // const statuses   = useMemo(() => ['all', 'Running', 'Terminated', 'OOMKilled', 'CrashLoopBackOff', 'Pending', 'Error'], []);

  const filtered = useMemo(() => podList.filter(p => {
    if (nsFilter !== 'all' && p.namespace !== nsFilter) return false;
    if (statusFilter !== 'all' && p.status !== statusFilter) return false;
    if (search && !p.name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  }), [podList, nsFilter, statusFilter, search]);

  const selectedPod   = selected ? pods[selected] : null;
  const podAlerts     = selected ? alerts.filter(a => a.pod === selected) : [];

  const getRisk = (p) => {
    if (p.status === 'OOMKilled' || p.status === 'CrashLoopBackOff') return { label: p.status.toUpperCase(), color: '#ff8c42' };
    if (p.status === 'Terminated') return { label: 'TERMINATED', color: '#4d7090' };
    if (p.threats === 0) return { label: 'CLEAN', color: '#06d6a0' };
    if (p.threats <= 2) return { label: 'LOW RISK', color: '#ffd166' };
    if (p.threats <= 5) return { label: 'HIGH RISK', color: '#ff8c42' };
    return { label: 'CRITICAL', color: '#ff3b3b' };
  };

  const btnStyle = (active) => ({
    padding: '4px 10px', borderRadius: 5, fontSize: 10, cursor: 'pointer',
    fontFamily: "'JetBrains Mono', monospace",
    border: `1px solid ${active ? '#00e5ff' : '#1a3050'}`,
    background: active ? 'rgba(0,229,255,.08)' : 'transparent',
    color: active ? '#00e5ff' : '#4d7090', transition: 'all .15s',
  });

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: '12px 20px', gap: 10, overflow: 'hidden' }}>

      {/* Toolbar */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0, flexWrap: 'wrap' }}>
        {/* Namespace filter */}
        <select value={nsFilter} onChange={e => setNsFilter(e.target.value)} style={{
          background: '#0d1b2e', border: '1px solid #1a3050', color: '#7090b0',
          padding: '4px 8px', borderRadius: 6, fontSize: 10,
          fontFamily: "'JetBrains Mono', monospace", cursor: 'pointer',
        }}>
          {namespaces.map(ns => <option key={ns} value={ns}>{ns === 'all' ? 'All Namespaces' : ns}</option>)}
        </select>

        {/* Status filter buttons */}
        <button onClick={() => setStatusFilter('all')} style={btnStyle(statusFilter === 'all')}>ALL</button>
        <button onClick={() => setStatusFilter('Running')} style={{ ...btnStyle(statusFilter === 'Running'), borderColor: statusFilter === 'Running' ? '#06d6a0' : '#1a3050', color: statusFilter === 'Running' ? '#06d6a0' : '#4d7090' }}>RUNNING</button>
        <button onClick={() => setStatusFilter('OOMKilled')} style={{ ...btnStyle(statusFilter === 'OOMKilled'), borderColor: statusFilter === 'OOMKilled' ? '#ff3b3b' : '#1a3050', color: statusFilter === 'OOMKilled' ? '#ff3b3b' : '#4d7090' }}>OOMKILLED</button>
        <button onClick={() => setStatusFilter('CrashLoopBackOff')} style={{ ...btnStyle(statusFilter === 'CrashLoopBackOff'), borderColor: statusFilter === 'CrashLoopBackOff' ? '#ff8c42' : '#1a3050', color: statusFilter === 'CrashLoopBackOff' ? '#ff8c42' : '#4d7090' }}>CRASHLOOP</button>
        <button onClick={() => setStatusFilter('Terminated')} style={{ ...btnStyle(statusFilter === 'Terminated'), borderColor: statusFilter === 'Terminated' ? '#4d7090' : '#1a3050' }}>TERMINATED</button>

        {/* Search */}
        <input placeholder="search pod..." value={search} onChange={e => setSearch(e.target.value)} style={{
          background: '#0d1b2e', border: '1px solid #1a3050', color: '#e2eaf7',
          padding: '4px 10px', borderRadius: 6, fontSize: 10,
          fontFamily: "'JetBrains Mono', monospace", outline: 'none', width: 160,
        }} />

        <Mono color="#4d7090" style={{ marginLeft: 'auto' }}>
          {filtered.length}/{podList.length} pods · {podList.filter(p=>p.threats>0).length} compromised
        </Mono>
        <ExportBtn label="CSV" icon="⬇" onClick={() => exportPodsCSV(pods)} />
        <ExportBtn label="JSON" icon="{}" onClick={() => exportJSON({ pods: podList, exported: new Date().toISOString() }, 'kubertsec-pods.json')} />
      </div>

      {/* Pod grid + detail */}
      <div style={{ flex: 1, display: 'flex', gap: 10, minHeight: 0, overflow: 'hidden' }}>

        {/* Pod grid */}
        <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
          <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr' : 'repeat(auto-fill, minmax(230px, 1fr))', gap: 8, alignContent: 'start' }}>
            {filtered.length === 0 ? (
              <div style={{ color: '#4d7090', fontSize: 12, padding: 20, gridColumn: '1/-1' }}>
                {podList.length === 0 ? 'Waiting for K8s sync — run: sudo KUBECONFIG=$HOME/.kube/config go run cmd/controller/main.go' : 'No pods match filters'}
              </div>
            ) : [...filtered]
              .sort((a,b) => {
                // Sort: OOM/Crash first, then by threats desc, then Running, then Terminated
                const statusPrio = (s) => { if(s==='OOMKilled'||s==='CrashLoopBackOff'||s==='Error') return 0; if(s==='Running') return 1; if(s==='Pending') return 2; return 3; };
                const sp = statusPrio(a.status) - statusPrio(b.status);
                if (sp !== 0) return sp;
                return (b.threats||0) - (a.threats||0);
              })
              .map(p => {
              const risk = getRisk(p);
              const sc   = STATUS_COLOR[p.status] || '#7090b0';
              const isSel = selected === p.name;
              const isDead = p.status === 'Terminated' || p.status === 'Completed';

              return (
                <div key={p.name} onClick={() => setSelected(isSel ? null : p.name)} style={{
                  background: isSel ? '#0d1f36' : '#0f1f36',
                  border: `1px solid ${isSel ? '#00e5ff' : p.threats > 0 ? 'rgba(255,59,59,.35)' : p.status === 'OOMKilled' ? 'rgba(255,59,59,.25)' : p.status === 'CrashLoopBackOff' ? 'rgba(255,140,66,.25)' : '#1a3050'}`,
                  borderRadius: 10, padding: '10px 12px', cursor: 'pointer',
                  transition: 'all .15s', opacity: isDead ? 0.65 : 1,
                }}>
                  {/* Header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 11, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", color: p.threats > 0 ? '#ffb3b3' : '#e2eaf7', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {p.name.length > 24 ? p.name.slice(0, 24) + '..' : p.name}
                      </div>
                      <div style={{ fontSize: 9, color: '#4d7090', marginTop: 1, fontFamily: "'JetBrains Mono', monospace" }}>{p.namespace}</div>
                    </div>
                    <span style={{ background: `${risk.color}18`, color: risk.color, border: `1px solid ${risk.color}40`, padding: '1px 6px', borderRadius: 3, fontSize: 8, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'nowrap', marginLeft: 6 }}>{risk.label}</span>
                  </div>

                  {/* Status + node */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: sc, boxShadow: isDead ? 'none' : `0 0 4px ${sc}`, flexShrink: 0 }} />
                      <span style={{ color: sc, fontSize: 9, fontFamily: "'JetBrains Mono', monospace" }}>{p.status}</span>
                    </span>
                    {p.restarts > 0 && <span style={{ fontSize: 9, color: p.restarts > 3 ? '#ff8c42' : '#4d7090', fontFamily: "'JetBrains Mono', monospace" }}>↺{p.restarts}</span>}
                    {p.node && <span style={{ fontSize: 9, color: '#2d4a60', fontFamily: "'JetBrains Mono', monospace", marginLeft: 'auto' }}>{p.node.slice(0,12)}</span>}
                  </div>

                  {/* Processes */}
                  {(p.processes||[]).length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginBottom: 6 }}>
                      {(p.processes||[]).slice(0,4).map(pr => <ProcTag key={pr} proc={pr} />)}
                      {(p.processes||[]).length > 4 && <span style={{ fontSize: 9, color: '#4d7090' }}>+{p.processes.length-4}</span>}
                    </div>
                  )}

                  {/* Alerts + image */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace" }}>
                    <span>alerts: <span style={{ color: p.threats > 0 ? '#ff3b3b' : '#06d6a0', fontWeight: 700 }}>{p.threats}</span></span>
                    {p.image && <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 100 }}>{p.image.split('/').pop()}</span>}
                  </div>
                  {p.threats > 0 && <div style={{ marginTop: 6 }}><ThreatBar value={p.threats} max={10} color={p.threats > 5 ? '#ff3b3b' : p.threats > 2 ? '#ff8c42' : '#ffd166'} /></div>}
                </div>
              );
            })}
          </div>
        </div>

        {/* Detail panel */}
        {selected && selectedPod && (
          <div style={{ width: 300, flexShrink: 0, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #0d1f33', flexShrink: 0, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7', fontFamily: "'JetBrains Mono', monospace", overflow: 'hidden', textOverflow: 'ellipsis', flex: 1 }}>
                {selectedPod.name.length > 22 ? selectedPod.name.slice(0, 22)+'..' : selectedPod.name}
              </span>
              <button onClick={() => setSelected(null)} style={{ background: 'transparent', border: '1px solid #1a3050', color: '#4d7090', padding: '3px 8px', borderRadius: 5, cursor: 'pointer', fontSize: 10, flexShrink: 0, marginLeft: 6 }}>✕</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>

              {/* Pod meta */}
              <div style={{ padding: '10px 14px', borderBottom: '1px solid #0d1f33', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 12px', fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>
                {[
                  ['namespace',  selectedPod.namespace],
                  ['status',     selectedPod.status],
                  ['phase',      selectedPod.phase || '—'],
                  ['ready',      selectedPod.ready ? 'true' : 'false'],
                  ['node',       selectedPod.node || '—'],
                  ['restarts',   selectedPod.restarts || 0],
                  ['threats',    selectedPod.threats],
                  ['last alert', selectedPod.lastEvent ? fmtTime(selectedPod.lastEvent) : '—'],
                ].map(([k, v]) => (
                  <div key={k}>
                    <div style={{ color: '#4d7090', fontSize: 9, marginBottom: 2 }}>{k}</div>
                    <div style={{
                      color: k==='threats' && v>0 ? '#ff3b3b' : k==='status' ? (STATUS_COLOR[v]||'#e2eaf7') : k==='ready' && v==='false' ? '#ff8c42' : '#e2eaf7',
                      fontWeight: k==='threats'?700:400,
                    }}>{String(v)}</div>
                  </div>
                ))}
              </div>

              {/* Image */}
              {selectedPod.image && (
                <div style={{ padding: '8px 14px', borderBottom: '1px solid #0d1f33', fontFamily: "'JetBrains Mono', monospace", fontSize: 9, color: '#4d7090' }}>
                  <div style={{ marginBottom: 2 }}>image</div>
                  <div style={{ color: '#7090b0', wordBreak: 'break-all' }}>{selectedPod.image}</div>
                </div>
              )}

              {/* Processes */}
              {(selectedPod.processes||[]).length > 0 && (
                <div style={{ padding: '10px 14px', borderBottom: '1px solid #0d1f33' }}>
                  <div style={{ fontSize: 9, color: '#4d7090', marginBottom: 6, fontFamily: "'JetBrains Mono', monospace" }}>PROCESSES SEEN ({(selectedPod.processes||[]).length})</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {(selectedPod.processes||[]).map(pr => <ProcTag key={pr} proc={pr} />)}
                  </div>
                </div>
              )}

              {/* Alert history */}
              <div style={{ padding: '10px 14px' }}>
                <div style={{ fontSize: 9, color: '#4d7090', marginBottom: 6, fontFamily: "'JetBrains Mono', monospace" }}>ALERT HISTORY ({podAlerts.length})</div>
                {podAlerts.length === 0
                  ? <div style={{ fontSize: 10, color: '#4d7090' }}>No alerts — pod is clean ✓</div>
                  : podAlerts.slice(0, 20).map(a => (
                    <div key={a.id} style={{ display: 'flex', gap: 6, padding: '6px 0', borderBottom: '1px solid #0d1f33' }}>
                      <SeverityBadge severity={a.severity} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 10, color: '#e2eaf7', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.message}</div>
                        <div style={{ fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace", marginTop: 1 }}>
                          <span style={{ color: '#00e5ff' }}>{a.process}</span> · {a.action}
                        </div>
                      </div>
                      <Mono color="#2d4a60">{fmtTime(a.timestamp)}</Mono>
                    </div>
                  ))}
              </div>
            </div>

            {/* Export */}
            <div style={{ padding: '8px 14px', borderTop: '1px solid #0d1f33', flexShrink: 0 }}>
              <ExportBtn label="Export Pod JSON" icon="⬇"
                onClick={() => exportJSON({ pod: selectedPod, alerts: podAlerts, exported: new Date().toISOString() }, `pod-${selectedPod.name}.json`)}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}