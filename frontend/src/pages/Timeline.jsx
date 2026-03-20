// pages/Timeline.jsx — fixed viewport, no page scroll
import React, { useMemo } from 'react';
import { useApp } from '../store/AppStore';
import { SeverityBadge, Mono, fmtTime, ExportBtn } from '../components/UI';
import { exportTimeline, exportJSON } from '../utils/export';

const SEV_COLOR = { critical: '#ff3b3b', high: '#ff8c42', medium: '#ffd166', low: '#4db8ff', info: '#4db8ff' };

const KILL_CHAIN = [
  { id: 'recon',   label: 'Reconnaissance', procs: ['nmap', 'masscan'],                  color: '#4db8ff', icon: '🔍' },
  { id: 'access',  label: 'Initial Access',  procs: ['curl', 'wget'],                     color: '#7c4dff', icon: '🌐' },
  { id: 'exec',    label: 'Execution',       procs: ['sh', 'bash', 'python'],             color: '#ffd166', icon: '⚡' },
  { id: 'persist', label: 'Persistence',     procs: ['crontab', 'systemctl'],             color: '#ff8c42', icon: '🔄' },
  { id: 'privesc', label: 'Privilege Esc',   procs: ['sudo', 'chmod', 'chown'],          color: '#ff8c42', icon: '⬆' },
  { id: 'escape',  label: 'Container Escape',procs: ['mount', 'nsenter', 'unshare'],     color: '#ff3b3b', icon: '🚨' },
  { id: 'exfil',   label: 'Exfiltration',    procs: ['nc', 'socat', 'openssl'],          color: '#ff3b3b', icon: '📤' },
];

export default function Timeline() {
  const { state } = useApp();
  const { alerts } = state;

  const killChainHits = useMemo(() => {
    const hits = {};
    KILL_CHAIN.forEach(stage => {
      hits[stage.id] = alerts.filter(a => stage.procs.some(p => (a.process || '').toLowerCase().includes(p)));
    });
    return hits;
  }, [alerts]);

  const attackGroups = useMemo(() => {
    const byPod = {};
    alerts.forEach(a => { if (!byPod[a.pod]) byPod[a.pod] = []; byPod[a.pod].push(a); });
    return byPod;
  }, [alerts]);

  const timeline = alerts.slice(0, 60);

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: '12px 20px', gap: 10, overflow: 'hidden' }}>

      {/* Toolbar */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0, justifyContent: 'flex-end' }}>
        <Mono color="#4d7090">{alerts.length} total events</Mono>
        <ExportBtn label="Timeline JSON" icon="⬇" onClick={() => exportTimeline(alerts)} />
        <ExportBtn label="Kill Chain" icon="📊" onClick={() => exportJSON({ killChain: KILL_CHAIN.map(s => ({ ...s, hits: killChainHits[s.id]?.length || 0 })), exported: new Date().toISOString() }, 'kubertsec-killchain.json')} />
      </div>

      {/* 3 columns: timeline | kill chain | attack groups */}
      <div style={{ flex: 1, display: 'flex', gap: 10, minHeight: 0, overflow: 'hidden' }}>

        {/* Attack chain */}
        <div style={{ flex: 2, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '10px 14px', borderBottom: '1px solid #0d1f33', flexShrink: 0, display: 'flex', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 3, height: 12, background: '#00e5ff', borderRadius: 2 }} />
              <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>Attack Chain</span>
            </div>
            <Mono color="#4d7090">{timeline.length} events</Mono>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', minHeight: 0, padding: '8px 14px' }}>
            {timeline.length === 0 ? (
              <div style={{ color: '#4d7090', fontSize: 11, padding: '16px 0' }}>No events yet.</div>
            ) : [...timeline].reverse().map((a, i) => {
              const isLast = i === timeline.length - 1;
              const color = SEV_COLOR[a.severity] || '#4db8ff';
              return (
                <div key={a.id} style={{ display: 'flex', gap: 12 }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <div style={{ width: 9, height: 9, borderRadius: '50%', border: `2px solid ${color}`, background: a.severity === 'critical' ? color : 'transparent', flexShrink: 0, marginTop: 4 }} />
                    {!isLast && <div style={{ width: 2, flex: 1, minHeight: 18, background: '#1a3050' }} />}
                  </div>
                  <div style={{ flex: 1, paddingBottom: 10 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color }}>{a.message}</div>
                    <div style={{ fontSize: 10, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace", marginTop: 2, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                      <span>pod: <span style={{ color: '#7090b0' }}>{a.pod.length > 18 ? a.pod.slice(0, 18) + '..' : a.pod}</span></span>
                      <span>proc: <span style={{ color: '#00e5ff' }}>{a.process}</span></span>
                      <span>ns: {a.namespace}</span>
                      <span style={{ marginLeft: 'auto' }}>{fmtTime(a.timestamp)}</span>
                    </div>
                    {(a.action === 'killed' || a.action === 'kill') && (
                      <div style={{ marginTop: 3, fontSize: 9, color: '#ff6b6b', background: 'rgba(255,59,59,.08)', border: '1px solid rgba(255,59,59,.2)', borderRadius: 3, padding: '1px 7px', display: 'inline-block', fontFamily: "'JetBrains Mono', monospace" }}>✕ Process killed</div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Kill chain */}
        <div style={{ width: 220, flexShrink: 0, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '10px 14px', borderBottom: '1px solid #0d1f33', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 3, height: 12, background: '#00e5ff', borderRadius: 2 }} />
              <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>MITRE Kill Chain</span>
            </div>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', minHeight: 0, padding: '10px 14px' }}>
            {KILL_CHAIN.map(stage => {
              const hits = killChainHits[stage.id] || [];
              const hit = hits.length > 0;
              const pct = hit ? Math.min(hits.length * 20, 100) : 0;
              return (
                <div key={stage.id} style={{ marginBottom: 14 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: hit ? stage.color : '#4d7090', fontWeight: hit ? 600 : 400 }}>{stage.icon} {stage.label}</span>
                    <Mono color={hit ? stage.color : '#2d4a60'}>{hit ? `${hits.length}` : '—'}</Mono>
                  </div>
                  <div style={{ height: 4, background: '#1a3050', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${pct}%`, background: stage.color, borderRadius: 2, transition: 'width .5s', boxShadow: hit ? `0 0 5px ${stage.color}60` : 'none' }} />
                  </div>
                  {hit && <div style={{ fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>{hits.slice(0, 2).map(h => h.process).join(', ')}{hits.length > 2 ? ` +${hits.length - 2}` : ''}</div>}
                </div>
              );
            })}
          </div>
        </div>

        {/* Attack groups by pod */}
        <div style={{ width: 220, flexShrink: 0, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '10px 14px', borderBottom: '1px solid #0d1f33', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 3, height: 12, background: '#00e5ff', borderRadius: 2 }} />
              <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>By Pod</span>
            </div>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
            {Object.keys(attackGroups).length === 0
              ? <div style={{ fontSize: 11, color: '#4d7090', padding: '12px 14px' }}>No groups</div>
              : Object.entries(attackGroups).map(([pod, podAlerts]) => {
                const hasCrit = podAlerts.some(a => a.severity === 'critical');
                const topSev = hasCrit ? 'critical' : podAlerts.some(a => a.severity === 'high') ? 'high' : 'medium';
                return (
                  <div key={pod} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 14px', borderBottom: '1px solid #0d1f33' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <Mono color="#e2eaf7">{pod.length > 18 ? pod.slice(0, 18) + '..' : pod}</Mono>
                      <div style={{ fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>
                        {[...new Set(podAlerts.map(a => a.process))].slice(0, 2).join(' → ')}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                      <SeverityBadge severity={topSev} />
                      <Mono color="#4d7090">{podAlerts.length}</Mono>
                    </div>
                  </div>
                );
              })}
          </div>
        </div>
      </div>
    </div>
  );
}
