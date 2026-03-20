// pages/Metrics.jsx — KubeRTSec Observability
// Frontend ONLY calls controller — URL comes from CONFIG
// Controller handles Prometheus + Grafana internally

import React, { useState, useEffect, useRef } from 'react';
import { useApp } from '../store/AppStore';
import { fmtTime } from '../components/UI';
import { api } from '../services/api';

// ── Sparkline ─────────────────────────────────────────────────────────────
function Sparkline({ values = [], color = '#00e5ff', height = 30, width = 100 }) {
  if (values.length < 2) return (
    <div style={{ width, height, display: 'flex', alignItems: 'center' }}>
      <span style={{ fontSize: 9, color: '#2d4a60', fontFamily: 'JetBrains Mono' }}>—</span>
    </div>
  );
  const max = Math.max(...values, 0.001);
  const min = Math.min(...values);
  const range = max - min || 1;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * width;
    const y = height - ((v - min) / range) * (height - 4) - 2;
    return `${x},${y}`;
  }).join(' ');
  const id = `sp${color.replace('#', '')}`;
  return (
    <svg width={width} height={height} style={{ display: 'block' }}>
      <defs>
        <linearGradient id={id} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.2" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,${height} ${pts} ${width},${height}`} fill={`url(#${id})`} />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// ── Status Pill ───────────────────────────────────────────────────────────
function Pill({ ok, label }) {
  const c = ok ? '#06d6a0' : '#ff3b3b';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 20, background: `${c}12`, border: `1px solid ${c}30` }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: c, boxShadow: ok ? `0 0 5px ${c}` : 'none' }} />
      <span style={{ fontSize: 10, color: c, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{label}</span>
    </div>
  );
}

// ── Metric Card ───────────────────────────────────────────────────────────
function MetricCard({ label, value, unit, color, spark, trend, icon }) {
  const tc = trend > 0 ? '#ff8c42' : trend < 0 ? '#06d6a0' : '#4d7090';
  return (
    <div style={{ background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, padding: '12px 14px', position: 'relative', overflow: 'hidden', flex: 1, minWidth: 0 }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: color }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <div>
          <div style={{ fontSize: 9, color: '#4d7090', fontFamily: 'JetBrains Mono', letterSpacing: '.5px', marginBottom: 4 }}>{label}</div>
          <div style={{ fontSize: 22, fontWeight: 800, color, lineHeight: 1 }}>
            {value}<span style={{ fontSize: 10, color: '#4d7090', marginLeft: 3 }}>{unit}</span>
          </div>
        </div>
        <span style={{ fontSize: 18, opacity: .8 }}>{icon}</span>
      </div>
      <Sparkline values={spark || []} color={color} width={100} height={26} />
      <div style={{ fontSize: 9, color: tc, fontFamily: 'JetBrains Mono', marginTop: 3 }}>
        {trend !== 0 ? (trend > 0 ? '▲' : '▼') : '─'} {Math.abs(trend || 0).toFixed(1)}%
      </div>
    </div>
  );
}

// ── Pod Resource Table ─────────────────────────────────────────────────────
function PodTable({ pods }) {
  return (
    <div style={{ flex: 1, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ padding: '8px 14px', borderBottom: '1px solid #0d1f33', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
        <div style={{ width: 3, height: 12, background: '#00e5ff', borderRadius: 2 }} />
        <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>Pod Resource Usage</span>
        <span style={{ fontSize: 9, color: '#4d7090', fontFamily: 'JetBrains Mono', marginLeft: 'auto' }}>via controller · 15s cache</span>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
          <thead style={{ position: 'sticky', top: 0, background: '#0f1f36', zIndex: 1 }}>
            <tr>
              {['POD', 'NS', 'CPU', 'CPU %', 'MEMORY', 'MEM %', 'NET RX', 'NET TX'].map(h => (
                <th key={h} style={{ padding: '5px 10px', textAlign: 'left', color: '#4d7090', fontWeight: 500, borderBottom: '1px solid #1a3050', fontFamily: 'JetBrains Mono', fontSize: 9, whiteSpace: 'nowrap' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pods.length === 0 ? (
              <tr><td colSpan={8} style={{ textAlign: 'center', color: '#4d7090', padding: 24, fontSize: 11 }}>
                Waiting for Prometheus data — run: <code style={{ color: '#00e5ff', fontSize: 9 }}>kubectl port-forward deployment/prometheus -n monitoring 9090:9090</code>
              </td></tr>
            ) : pods.map((p, i) => {
              const cpuPct = Math.min((p.cpu / 0.5) * 100, 100);
              const memPct = Math.min((p.memoryMi / 256) * 100, 100);
              const cpuC = cpuPct > 80 ? '#ff3b3b' : cpuPct > 50 ? '#ff8c42' : '#06d6a0';
              const memC = memPct > 80 ? '#ff3b3b' : memPct > 50 ? '#ff8c42' : '#4db8ff';
              return (
                <tr key={i}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,.02)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '5px 10px', borderBottom: '1px solid #0d1f33', fontFamily: 'JetBrains Mono', fontSize: 10, color: '#e2eaf7', whiteSpace: 'nowrap' }}>
                    {p.pod.length > 26 ? p.pod.slice(0, 26) + '..' : p.pod}
                  </td>
                  <td style={{ padding: '5px 10px', borderBottom: '1px solid #0d1f33' }}>
                    <span style={{ background: 'rgba(77,184,255,.08)', color: '#80ccff', border: '1px solid rgba(77,184,255,.2)', padding: '1px 5px', borderRadius: 3, fontSize: 9, fontFamily: 'JetBrains Mono' }}>{p.namespace}</span>
                  </td>
                  <td style={{ padding: '5px 10px', borderBottom: '1px solid #0d1f33', fontFamily: 'JetBrains Mono', fontSize: 10, color: cpuC }}>{(p.cpu || 0).toFixed(4)}c</td>
                  <td style={{ padding: '5px 10px', borderBottom: '1px solid #0d1f33', minWidth: 80 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{ flex: 1, height: 4, background: '#1a3050', borderRadius: 2 }}>
                        <div style={{ height: '100%', width: `${cpuPct}%`, background: cpuC, borderRadius: 2, transition: 'width .5s' }} />
                      </div>
                      <span style={{ fontSize: 9, color: cpuC, fontFamily: 'JetBrains Mono', minWidth: 26 }}>{cpuPct.toFixed(0)}%</span>
                    </div>
                  </td>
                  <td style={{ padding: '5px 10px', borderBottom: '1px solid #0d1f33', fontFamily: 'JetBrains Mono', fontSize: 10, color: memC }}>{(p.memoryMi || 0).toFixed(0)}Mi</td>
                  <td style={{ padding: '5px 10px', borderBottom: '1px solid #0d1f33', minWidth: 80 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{ flex: 1, height: 4, background: '#1a3050', borderRadius: 2 }}>
                        <div style={{ height: '100%', width: `${memPct}%`, background: memC, borderRadius: 2, transition: 'width .5s' }} />
                      </div>
                      <span style={{ fontSize: 9, color: memC, fontFamily: 'JetBrains Mono', minWidth: 26 }}>{memPct.toFixed(0)}%</span>
                    </div>
                  </td>
                  <td style={{ padding: '5px 10px', borderBottom: '1px solid #0d1f33', fontFamily: 'JetBrains Mono', fontSize: 9, color: '#06d6a0' }}>{(p.netRxKBs || 0).toFixed(1)} KB/s</td>
                  <td style={{ padding: '5px 10px', borderBottom: '1px solid #0d1f33', fontFamily: 'JetBrains Mono', fontSize: 9, color: '#7c4dff' }}>{(p.netTxKBs || 0).toFixed(1)} KB/s</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Grafana Section ───────────────────────────────────────────────────────
function GrafanaSection({ grafana }) {
  if (!grafana) return null;
  return (
    <div style={{ background: '#0f1f36', border: `1px solid ${grafana.healthy ? 'rgba(124,77,255,.35)' : '#1a3050'}`, borderRadius: 10, padding: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <div style={{ width: 3, height: 12, background: '#7c4dff', borderRadius: 2 }} />
        <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>Grafana</span>
        <Pill ok={grafana.healthy} label={grafana.healthy ? `v${grafana.version || '?'} ONLINE` : 'OFFLINE'} />
      </div>
      {grafana.healthy ? (
        <>
          <a href={grafana.url} target="_blank" rel="noreferrer" style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
            background: 'rgba(124,77,255,.15)', color: '#c5a3ff',
            border: '1px solid rgba(124,77,255,.3)', padding: '9px',
            borderRadius: 7, fontSize: 12, fontFamily: 'JetBrains Mono',
            textDecoration: 'none', fontWeight: 600, marginBottom: 10,
          }}>
            📊 Open Grafana ↗
          </a>
          {(grafana.dashboards || []).map((d, i) => (
            <a key={i} href={`${grafana.url}${d.url}`} target="_blank" rel="noreferrer" style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '6px 8px', borderRadius: 6, marginBottom: 4,
              background: 'rgba(124,77,255,.06)', border: '1px solid rgba(124,77,255,.1)',
              textDecoration: 'none',
            }}>
              <span style={{ fontSize: 11 }}>📈</span>
              <span style={{ fontSize: 10, color: '#c5a3ff', fontFamily: 'JetBrains Mono', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.title}</span>
              <span style={{ fontSize: 9, color: '#4d7090' }}>↗</span>
            </a>
          ))}
          {(grafana.dashboards || []).length === 0 && (
            <div style={{ fontSize: 9, color: '#4d7090', fontFamily: 'JetBrains Mono' }}>
              No dashboards found. KubeRTSec dashboard auto-creates on first run.
            </div>
          )}
        </>
      ) : (
        <div style={{ fontSize: 9, color: '#7090b0', lineHeight: 1.7, fontFamily: 'JetBrains Mono' }}>
          Start Grafana:<br />
          <span style={{ color: '#7c4dff' }}>kubectl port-forward deployment/grafana -n monitoring 3001:3000</span><br />
          Or set: <span style={{ color: '#7c4dff' }}>GRAFANA_URL=http://grafana-svc:3000</span>
        </div>
      )}
    </div>
  );
}

// ── Namespace Breakdown ────────────────────────────────────────────────────
function NsBreakdown({ pods, totalCpu }) {
  const byNs = pods.reduce((acc, p) => {
    if (!acc[p.namespace]) acc[p.namespace] = { cpu: 0, mem: 0, count: 0 };
    acc[p.namespace].cpu += p.cpu || 0;
    acc[p.namespace].mem += p.memoryMi || 0;
    acc[p.namespace].count += 1;
    return acc;
  }, {});
  const sorted = Object.entries(byNs).sort((a, b) => b[1].cpu - a[1].cpu);
  return (
    <div style={{ background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: '8px 14px', borderBottom: '1px solid #0d1f33', display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ width: 3, height: 12, background: '#00e5ff', borderRadius: 2 }} />
        <span style={{ fontSize: 11, fontWeight: 600, color: '#e2eaf7' }}>By Namespace</span>
      </div>
      <div style={{ padding: '10px 14px' }}>
        {sorted.length === 0
          ? <div style={{ fontSize: 10, color: '#4d7090', textAlign: 'center', padding: 8 }}>No data</div>
          : sorted.map(([ns, m]) => (
            <div key={ns} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                <span style={{ fontSize: 10, color: '#80ccff', fontFamily: 'JetBrains Mono' }}>{ns}</span>
                <span style={{ fontSize: 9, color: '#4d7090', fontFamily: 'JetBrains Mono' }}>
                  {m.count}p · {m.cpu.toFixed(3)}c · {m.mem.toFixed(0)}Mi
                </span>
              </div>
              <div style={{ height: 4, background: '#1a3050', borderRadius: 2 }}>
                <div style={{ height: '100%', width: `${Math.min((m.cpu / (totalCpu || 1)) * 100, 100)}%`, background: 'linear-gradient(90deg,#00e5ff,#7c4dff)', borderRadius: 2, transition: 'width .5s' }} />
              </div>
            </div>
          ))
        }
      </div>
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────
export default function Metrics() {
  const { state } = useApp();
  const { alerts, pods: storePods, stats } = state;

  const [monitoring, setMonitoring] = useState(null);
  const [cluster, setCluster] = useState(null);
  const [cpuHist, setCpuHist] = useState([]);
  const [memHist, setMemHist] = useState([]);
  const [netHist, setNetHist] = useState([]);
  const [lastRefresh, setLastRefresh] = useState(null);
  const intervalRef = useRef(null);

  const fetchAll = async () => {
    try {
      const [monData, clusterData] = await Promise.all([
        api.status.get().catch(() => null),
        api.metrics.cluster().catch(() => null),
      ]);
      if (monData) setMonitoring(monData);
      if (clusterData) {
        setCluster(clusterData);
        setCpuHist(h => [...h.slice(-29), clusterData.totalCPU || 0]);
        setMemHist(h => [...h.slice(-29), clusterData.totalMemoryMi || 0]);
        setNetHist(h => [...h.slice(-29), clusterData.totalNetRxKBs || 0]);
      }
      setLastRefresh(new Date());
    } catch (e) {
      console.warn('[Metrics] fetch error:', e);
    }
  };

  useEffect(() => {
    fetchAll();
    intervalRef.current = setInterval(fetchAll, 15000); // CONFIG.METRICS_INTERVAL
    return () => clearInterval(intervalRef.current);
  }, []);

  const trend = arr => {
    if (arr.length < 2) return 0;
    const prev = arr[arr.length - 2] || 0;
    const curr = arr[arr.length - 1] || 0;
    if (!prev) return 0;
    return ((curr - prev) / prev) * 100;
  };

  const podList = Object.values(storePods);
  const promOk = monitoring?.monitoring?.prometheus?.healthy || monitoring?.prometheus?.healthy || cluster?.healthy || false;
  const grafanaOk = monitoring?.monitoring?.grafana?.healthy || false;
  const pods = cluster?.pods || [];
  const totalCpu = cluster?.totalCPU || 0;
  const totalMem = cluster?.totalMemoryMi || 0;
  const totalNet = cluster?.totalNetRxKBs || 0;
  const alertRate = alerts.filter(a => (Date.now() - new Date(a.timestamp)) < 300000).length;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: '12px 20px', gap: 10, overflow: 'hidden' }}>

      {/* Status bar */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
        <Pill ok={true} label="KubeRTSec ✓" />
        <Pill ok={promOk} label={`Prometheus ${promOk ? '✓' : '✗'}`} />
        <Pill ok={grafanaOk} label={`Grafana ${grafanaOk ? '✓' : '✗'}`} />
        <span style={{ marginLeft: 'auto', fontSize: 9, color: '#4d7090', fontFamily: 'JetBrains Mono' }}>
          {lastRefresh ? `synced ${fmtTime(lastRefresh)}` : 'connecting...'}
        </span>
      </div>

      {/* Metric cards */}
      <div style={{ display: 'flex', gap: 10, flexShrink: 0 }}>
        <MetricCard label="CLUSTER CPU" value={totalCpu.toFixed(3)} unit="cores" color="#00e5ff" spark={cpuHist} trend={trend(cpuHist)} icon="⚡" />
        <MetricCard label="CLUSTER MEMORY" value={totalMem.toFixed(0)} unit="Mi" color="#7c4dff" spark={memHist} trend={trend(memHist)} icon="💾" />
        <MetricCard label="NETWORK IN" value={totalNet.toFixed(1)} unit="KB/s" color="#06d6a0" spark={netHist} trend={trend(netHist)} icon="🌐" />
        <MetricCard label="ALERT RATE" value={alertRate} unit="/5min" color={alertRate > 5 ? '#ff3b3b' : '#ff8c42'} spark={[]} trend={0} icon="🚨" />
        <MetricCard
          label="PODS RUNNING"
          value={stats.podsRunning || podList.filter(p => p.status === 'Running').length}
          unit={`/ ${stats.podsTotal || podList.length}`}
          color="#ffd166" spark={[]} trend={0} icon="🐳"
        />
      </div>

      {/* Pod table + right panel */}
      <div style={{ flex: 1, display: 'flex', gap: 10, minHeight: 0, overflow: 'hidden' }}>

        {/* Pod table */}
        <div style={{ flex: 3, minHeight: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <PodTable pods={pods} />
        </div>

        {/* Right: Grafana + Namespace */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 10, minHeight: 0, overflowY: 'auto' }}>
          <GrafanaSection grafana={monitoring?.monitoring?.grafana} />
          <NsBreakdown pods={pods} totalCpu={totalCpu} />

          {/* Prometheus setup hint */}
          {!promOk && (
            <div style={{ background: 'rgba(255,209,102,.05)', border: '1px solid rgba(255,209,102,.2)', borderRadius: 10, padding: '12px 14px' }}>
              <div style={{ fontSize: 10, color: '#ffd166', fontWeight: 600, marginBottom: 6, fontFamily: 'JetBrains Mono' }}>⚠ Prometheus Setup</div>
              <div style={{ fontSize: 9, color: '#7090b0', lineHeight: 1.8, fontFamily: 'JetBrains Mono' }}>
                Run:<br />
                <span style={{ color: '#00e5ff' }}>kubectl port-forward deployment/prometheus \</span><br />
                <span style={{ color: '#00e5ff' }}>  -n monitoring 9090:9090</span><br /><br />
                Or set env on controller:<br />
                <span style={{ color: '#00e5ff' }}>PROMETHEUS_URL=http://prometheus-svc.monitoring:9090</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}