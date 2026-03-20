// pages/Overview.jsx — Production Runtime Security Overview
import React, { useMemo } from 'react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { useApp } from '../store/AppStore';
import { SeverityBadge, NsTag, Mono, fmtTime, ExportBtn } from '../components/UI';
import { exportAlertsCSV, exportSecurityReport } from '../utils/export';

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

const HEALTH_STYLE = {
  OK:       { color: '#06d6a0', bg: 'rgba(6,214,160,.08)',   border: 'rgba(6,214,160,.2)'   },
  WARN:     { color: '#ffd166', bg: 'rgba(255,209,102,.08)', border: 'rgba(255,209,102,.2)' },
  CRITICAL: { color: '#ff3b3b', bg: 'rgba(255,59,59,.08)',   border: 'rgba(255,59,59,.2)'   },
};

function StatCard({ label, value, color, sub, accent }) {
  return (
    <div style={{
      background: '#0f1f36', border: `1px solid ${accent || '#1a3050'}`,
      borderRadius: 10, padding: '12px 16px',
      position: 'relative', overflow: 'hidden', flex: 1, minWidth: 0,
    }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: color }} />
      <div style={{ fontSize: 9, color: '#4d7090', letterSpacing: '.5px', marginBottom: 6, fontFamily: "'JetBrains Mono', monospace" }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 800, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 10, color: '#4d7090', marginTop: 4, fontFamily: "'JetBrains Mono', monospace" }}>{sub}</div>
    </div>
  );
}

function MiniStat({ label, value, color }) {
  return (
    <div style={{ textAlign: 'center', padding: '6px 10px' }}>
      <div style={{ fontSize: 16, fontWeight: 800, color: color || '#e2eaf7' }}>{value}</div>
      <div style={{ fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>{label}</div>
    </div>
  );
}

export default function Overview() {
  const { state } = useApp();
  const { alerts, pods, stats, posture, chartData, lastSync } = state;

  const chartPoints = chartData.map((v, i) => ({ i, v }));
  const podList = Object.values(pods);

  const sevDist = useMemo(() => {
    const bySev = stats.bySeverity || {};
    return [
      { name: 'Crit', value: bySev.critical || 0, fill: '#ff3b3b' },
      { name: 'High', value: bySev.high     || 0, fill: '#ff8c42' },
      { name: 'Med',  value: bySev.medium   || 0, fill: '#ffd166' },
      { name: 'Low',  value: bySev.low      || 0, fill: '#4db8ff' },
    ];
  }, [stats.bySeverity]);

  const health = stats.clusterHealth || 'OK';
  const hs = HEALTH_STYLE[health] || HEALTH_STYLE.OK;

  const postureScore = posture?.score ?? null;
  const postureColor = postureScore === null ? '#4d7090'
    : postureScore >= 70 ? '#06d6a0'
    : postureScore >= 40 ? '#ffd166'
    : '#ff3b3b';

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: '12px 20px', gap: 10, overflow: 'hidden' }}>

      {/* Row 1: Cluster Health Banner + Stats */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'stretch', flexShrink: 0 }}>

        {/* Health Banner */}
        <div style={{
          background: hs.bg, border: `1px solid ${hs.border}`,
          borderRadius: 10, padding: '10px 16px',
          display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minWidth: 140,
        }}>
          <div style={{ fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace", letterSpacing: '.5px' }}>CLUSTER HEALTH</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: hs.color }}>{health}</div>
          <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
            <MiniStat label="RUN"  value={stats.podsRunning    || 0} color="#06d6a0" />
            <MiniStat label="FAIL" value={stats.podsFailed     || 0} color="#ff8c42" />
            <MiniStat label="TERM" value={stats.podsTerminated || 0} color="#4d7090" />
          </div>
        </div>

        {/* Stat cards */}
        <StatCard
          label="THREATS TOTAL"
          value={stats.threats || 0}
          color="#ff3b3b"
          sub={`${stats.lastHour || 0} last hour · ${stats.last24h || 0} last 24h`}
        />
        <StatCard
          label="PROCESSES KILLED"
          value={stats.blocked || 0}
          color="#ff8c42"
          sub="enforce mode kills"
        />
        <StatCard
          label="PODS MONITORED"
          value={stats.podsTotal || podList.length}
          color="#4db8ff"
          sub={`${stats.namespaceCount || 0} namespaces`}
        />
        <StatCard
          label="COMPROMISED PODS"
          value={stats.compromisedPods || 0}
          color="#ff3b3b"
          sub="with active alerts"
          accent={stats.compromisedPods > 0 ? 'rgba(255,59,59,.3)' : '#1a3050'}
        />

        {/* Posture Score */}
        <div style={{
          background: '#0f1f36', border: '1px solid #1a3050',
          borderRadius: 10, padding: '10px 16px',
          display: 'flex', flexDirection: 'column', justifyContent: 'space-between',
          minWidth: 110, position: 'relative', overflow: 'hidden',
        }}>
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: postureColor }} />
          <div style={{ fontSize: 9, color: '#4d7090', letterSpacing: '.5px', fontFamily: "'JetBrains Mono', monospace" }}>POSTURE SCORE</div>
          <div style={{ fontSize: 28, fontWeight: 800, color: postureColor, lineHeight: 1 }}>
            {postureScore !== null ? postureScore : '—'}
          </div>
          <div style={{ fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace", marginTop: 4 }}>
            {posture ? `${posture.findings?.length || 0} findings` : 'loading...'}
          </div>
        </div>

        {/* Export */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, justifyContent: 'center' }}>
          <ExportBtn label="CSV"    icon="⬇"  onClick={() => exportAlertsCSV(alerts)} />
          <ExportBtn label="Report" icon="📋" onClick={() => exportSecurityReport({ alerts, pods, stats })} />
        </div>
      </div>

      {/* Row 2: Charts */}
      <div style={{ display: 'flex', gap: 10, flexShrink: 0, height: 118 }}>
        <div style={{ flex: 2, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, padding: '8px 14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 3, height: 12, background: '#00e5ff', borderRadius: 2 }} />
              <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>Alert Rate</span>
            </div>
            <Mono color="#4d7090">{stats.lastHour || 0}/hr · {lastSync ? `sync ${fmtTime(lastSync)}` : 'syncing...'}</Mono>
          </div>
          <ResponsiveContainer width="100%" height={76}>
            <LineChart data={chartPoints}>
              <Line type="monotone" dataKey="v" stroke="#00e5ff" strokeWidth={1.5} dot={false} />
              <YAxis hide domain={[0, 'auto']} />
              <XAxis hide />
              <Tooltip
                contentStyle={{ background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 6, fontSize: 10 }}
                itemStyle={{ color: '#00e5ff' }}
                labelFormatter={() => ''}
                formatter={v => [v, 'Alerts']}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div style={{ flex: 1, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, padding: '8px 14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <div style={{ width: 3, height: 12, background: '#00e5ff', borderRadius: 2 }} />
            <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>By Severity</span>
          </div>
          <ResponsiveContainer width="100%" height={76}>
            <BarChart data={sevDist} barSize={20}>
              <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#4d7090', fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
              <YAxis hide />
              <Tooltip
                contentStyle={{ background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 6, fontSize: 10 }}
                cursor={{ fill: 'rgba(255,255,255,.03)' }}
              />
              <Bar dataKey="value" radius={[3,3,0,0]}>
                {sevDist.map((e, i) => <rect key={i} fill={e.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Row 3: Pods Table + Live Feed */}
      <div style={{ flex: 1, display: 'flex', gap: 10, minHeight: 0, overflow: 'hidden' }}>

        {/* Pods table */}
        <div style={{ flex: 2, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '8px 14px 6px', flexShrink: 0, borderBottom: '1px solid #0d1f33' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 3, height: 12, background: '#00e5ff', borderRadius: 2 }} />
                <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>All Pods</span>
                <span style={{ fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace" }}>
                  ({podList.filter(p => p.status === 'Running').length} running / {podList.length} total)
                </span>
              </div>
              <Mono color="#4d7090">{fmtTime(new Date())}</Mono>
            </div>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead style={{ position: 'sticky', top: 0, background: '#0f1f36', zIndex: 1 }}>
                <tr>
                  {['NS','POD','STATUS','NODE','IP','THREATS','LAST ALERT'].map(h => (
                    <th key={h} style={{
                      padding: '5px 10px', textAlign: 'left', color: '#4d7090',
                      fontWeight: 500, borderBottom: '1px solid #1a3050',
                      fontFamily: "'JetBrains Mono', monospace", fontSize: 9,
                      letterSpacing: '.5px', whiteSpace: 'nowrap',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {podList.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', color: '#4d7090', padding: 20 }}>
                      Waiting for K8s sync...
                    </td>
                  </tr>
                ) : [...podList]
                  .sort((a, b) => (b.threats || 0) - (a.threats || 0))
                  .map(p => {
                    const sc = STATUS_COLOR[p.status] || '#7090b0';
                    const isDim = ['Terminated','Completed'].includes(p.status);
                    return (
                      <tr
                        key={p.name}
                        style={{ opacity: isDim ? 0.5 : 1 }}
                        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,.02)'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                      >
                        <td style={{ padding: '6px 10px', borderBottom: '1px solid #0d1f33' }}><NsTag ns={p.namespace} /></td>
                        <td style={{ padding: '6px 10px', borderBottom: '1px solid #0d1f33' }}>
                          <Mono color={p.threats > 0 ? '#ffb3b3' : '#e2eaf7'}>
                            {p.name.length > 28 ? p.name.slice(0,28)+'..' : p.name}
                          </Mono>
                        </td>
                        <td style={{ padding: '6px 10px', borderBottom: '1px solid #0d1f33' }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: sc, boxShadow: isDim ? 'none' : `0 0 4px ${sc}` }} />
                            <span style={{ color: sc, fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}>{p.status}</span>
                          </span>
                        </td>
                        <td style={{ padding: '6px 10px', borderBottom: '1px solid #0d1f33' }}>
                          <Mono color="#4d7090">{p.node ? p.node.slice(0,16) : '—'}</Mono>
                        </td>
                        <td style={{ padding: '6px 10px', borderBottom: '1px solid #0d1f33' }}>
                          <Mono color="#2d4a60">{p.ip || '—'}</Mono>
                        </td>
                        <td style={{ padding: '6px 10px', borderBottom: '1px solid #0d1f33', fontWeight: p.threats > 0 ? 700 : 400, color: p.threats > 0 ? '#ff3b3b' : '#4d7090', fontSize: 11 }}>
                          {p.threats > 0 ? `⚠ ${p.threats}` : '✓ 0'}
                        </td>
                        <td style={{ padding: '6px 10px', borderBottom: '1px solid #0d1f33' }}>
                          <Mono color="#2d4a60">{p.lastEvent ? fmtTime(p.lastEvent) : '—'}</Mono>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Live Feed */}
        <div style={{ flex: 1, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '8px 14px 6px', flexShrink: 0, borderBottom: '1px solid #0d1f33' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 3, height: 12, background: '#00e5ff', borderRadius: 2 }} />
                <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>Live Feed</span>
              </div>
              <span style={{ fontSize: 9, color: '#06d6a0', fontFamily: "'JetBrains Mono', monospace" }}>● LIVE</span>
            </div>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
            {alerts.length === 0 ? (
              <div style={{ textAlign: 'center', color: '#4d7090', padding: 24, fontSize: 11 }}>
                No alerts. Monitoring active.
              </div>
            ) : alerts.slice(0, 50).map(a => (
              <div key={a.id} style={{ display: 'flex', gap: 8, padding: '7px 12px', borderBottom: '1px solid #0d1f33' }}>
                <SeverityBadge severity={a.severity} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11, fontWeight: 500, color: '#e2eaf7', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {a.message}
                  </div>
                  <div style={{ fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>
                    {a.pod.length > 18 ? a.pod.slice(0,18)+'..' : a.pod}
                    {' · '}
                    <span style={{ color: '#00e5ff' }}>{a.process}</span>
                    {a.killed && <span style={{ color: '#ff3b3b', marginLeft: 4 }}>KILLED</span>}
                  </div>
                </div>
                <div style={{ fontSize: 9, color: '#2d4a60', fontFamily: "'JetBrains Mono', monospace", whiteSpace: 'nowrap' }}>
                  {fmtTime(a.timestamp)}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
