// App.jsx — KubeRTSec Production Dashboard
import React, { useState, useEffect, useRef } from 'react';
import { AppProvider, useApp } from './store/AppStore';
import { ToastProvider, useToast } from './components/Toast';
import Overview  from './pages/Overview';
import Alerts    from './pages/Alerts';
import Pods      from './pages/Pods';
import Timeline  from './pages/Timeline';
import Rules     from './pages/Rules';
import Metrics   from './pages/Metrics';
import CONFIG    from './config';

// ── Page definitions ─────────────────────────────────────────────────────────

const PAGES = [
  {
    id: 'overview', label: 'Overview', group: 'MONITOR',
    icon: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" width="16" height="16"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>,
  },
  {
    id: 'alerts', label: 'Live Alerts', group: 'MONITOR',
    icon: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" width="16" height="16"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    badge: true,
  },
  {
    id: 'pods', label: 'Pod Security', group: 'MONITOR',
    icon: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" width="16" height="16"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>,
  },
  {
    id: 'metrics', label: 'Metrics', group: 'OBSERVE',
    icon: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" width="16" height="16"><path d="M3 3v18h18"/><path d="M18.7 8l-5.1 5.2-2.8-2.7L7 14.3"/></svg>,
    grafana: true,
  },
  {
    id: 'timeline', label: 'Attack Timeline', group: 'ANALYZE',
    icon: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" width="16" height="16"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  },
  {
    id: 'rules', label: 'Rules', group: 'ANALYZE',
    icon: <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" width="16" height="16"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>,
  },
];

const PAGE_COMPONENTS = {
  overview: Overview,
  alerts:   Alerts,
  pods:     Pods,
  metrics:  Metrics,
  timeline: Timeline,
  rules:    Rules,
};

// ── Backend offline banner ────────────────────────────────────────────────────

function OfflineBanner({ apiUrl }) {
  const { state, actions } = useApp();
  if (state.backendOnline !== false) return null;
  return (
    <div style={{
      background: 'rgba(255,59,59,.12)',
      border: '1px solid rgba(255,59,59,.3)',
      borderRadius: 8,
      padding: '8px 16px',
      margin: '8px 16px 0',
      display: 'flex',
      alignItems: 'center',
      gap: 10,
      fontSize: 12,
      color: '#ff8080',
      flexShrink: 0,
    }}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="14" height="14">
        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <span>
        Controller offline — <code style={{ fontSize: 10, color: '#ff8080' }}>{apiUrl}</code>
        {' '}
        <span style={{ color: '#7090b0' }}>Run: <code style={{ color: '#00e5ff' }}>make controller</code> or set <code style={{ color: '#00e5ff' }}>REACT_APP_API_URL</code></span>
      </span>
      <button
        onClick={actions.reconnectWS}
        style={{
          marginLeft: 'auto', fontSize: 10, padding: '3px 10px',
          background: 'rgba(255,59,59,.15)', border: '1px solid rgba(255,59,59,.3)',
          color: '#ff8080', borderRadius: 5, cursor: 'pointer',
        }}
      >
        retry
      </button>
    </div>
  );
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

function Sidebar({ activePage, setActivePage }) {
  const { state, actions } = useApp();
  const { wsStatus, alerts, pods } = state;
  const critHighCount = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;

  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const wsConnected = wsStatus === 'connected';
  const groups = [...new Set(PAGES.map(p => p.group))];

  return (
    <nav style={{
      width: 220, minWidth: 220,
      background: '#0d1b2e',
      borderRight: '1px solid #1a3050',
      display: 'flex', flexDirection: 'column',
      height: '100vh', overflow: 'hidden',
    }}>
      {/* Logo */}
      <div style={{ padding: '20px 18px 14px', borderBottom: '1px solid #0f2a47' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 34, height: 34,
            background: 'linear-gradient(135deg, #00e5ff, #7c4dff)',
            borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" width="18" height="18">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/>
            </svg>
          </div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 800, color: '#fff', letterSpacing: '.5px' }}>KubeRTSec</div>
            <div style={{ fontSize: 9, color: '#4d7090', letterSpacing: '1.5px', fontFamily: "'JetBrains Mono', monospace" }}>
              RUNTIME SECURITY
            </div>
          </div>
        </div>

        {/* WS status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 12 }}>
          <div style={{
            width: 6, height: 6, borderRadius: '50%',
            background: wsConnected ? '#06d6a0' : wsStatus === 'connecting' ? '#ffd166' : '#ff3b3b',
            boxShadow: `0 0 6px ${wsConnected ? '#06d6a0' : wsStatus === 'connecting' ? '#ffd166' : '#ff3b3b'}`,
            animation: wsConnected ? 'pulse 2s infinite' : 'none',
          }} />
          <span style={{ fontSize: 10, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace" }}>
            {wsStatus === 'connected' ? 'WS LIVE' : wsStatus === 'connecting' ? 'WS CONNECTING…' : 'WS OFFLINE'}
          </span>
          {wsStatus !== 'connected' && (
            <button onClick={actions.reconnectWS} style={{
              marginLeft: 'auto', fontSize: 9,
              background: 'transparent', border: '1px solid #1a3050',
              color: '#4d7090', padding: '2px 6px', borderRadius: 4, cursor: 'pointer',
              fontFamily: "'JetBrains Mono', monospace",
            }}>
              retry
            </button>
          )}
        </div>

        {/* Backend URL hint */}
        <div style={{ marginTop: 6, fontSize: 9, color: '#2d4060', fontFamily: "'JetBrains Mono', monospace", wordBreak: 'break-all' }}>
          {CONFIG.API_URL}
        </div>
      </div>

      {/* Nav items */}
      <div style={{ flex: 1, padding: '8px 0', overflowY: 'auto' }}>
        {groups.map(group => (
          <div key={group}>
            <div style={{
              padding: '14px 18px 4px',
              fontSize: 9, color: '#2d4a60',
              letterSpacing: '1.5px', fontFamily: "'JetBrains Mono', monospace",
            }}>
              {group}
            </div>
            {PAGES.filter(p => p.group === group).map(page => {
              const isActive = activePage === page.id;
              const activeColor  = page.grafana ? '#c5a3ff' : '#00e5ff';
              const activeBorder = page.grafana ? '#7c4dff' : '#00e5ff';
              const activeBg     = page.grafana ? 'rgba(124,77,255,.06)' : 'rgba(0,229,255,.06)';
              return (
                <div
                  key={page.id}
                  onClick={() => setActivePage(page.id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '10px 18px', cursor: 'pointer',
                    fontSize: 13, fontWeight: 500,
                    color: isActive ? activeColor : '#4d7090',
                    borderLeft: `3px solid ${isActive ? activeBorder : 'transparent'}`,
                    background: isActive ? activeBg : 'transparent',
                    transition: 'all .15s',
                  }}
                  onMouseEnter={e => { if (!isActive) { e.currentTarget.style.color = '#e2eaf7'; e.currentTarget.style.background = 'rgba(255,255,255,.03)'; } }}
                  onMouseLeave={e => { if (!isActive) { e.currentTarget.style.color = '#4d7090'; e.currentTarget.style.background = 'transparent'; } }}
                >
                  {page.icon}
                  {page.label}
                  {page.grafana && (
                    <span style={{ marginLeft: 'auto', fontSize: 8, background: 'rgba(124,77,255,.2)', color: '#c5a3ff', padding: '1px 5px', borderRadius: 3, fontFamily: 'JetBrains Mono' }}>
                      PROM
                    </span>
                  )}
                  {page.badge && critHighCount > 0 && (
                    <span style={{
                      marginLeft: 'auto',
                      background: 'rgba(255,59,59,.15)', color: '#ff6b6b',
                      fontSize: 10, padding: '2px 6px', borderRadius: 10,
                      fontFamily: "'JetBrains Mono', monospace",
                    }}>
                      {critHighCount}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>

      {/* Footer */}
      <div style={{ padding: '14px 18px', borderTop: '1px solid #0f2a47' }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: '#7090b0', marginBottom: 2 }}>prod-cluster-01</div>
        <div style={{ fontSize: 10, color: '#2d4a60', fontFamily: "'JetBrains Mono', monospace" }}>
          {Object.keys(pods).length} pods monitored
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
          <div style={{ fontSize: 9, color: '#2d4a60', fontFamily: "'JetBrains Mono', monospace" }}>
            v{CONFIG.VERSION}
          </div>
          <div style={{ fontSize: 11, color: '#2d4a60', fontFamily: "'JetBrains Mono', monospace" }}>
            {time.toLocaleTimeString('en-IN', { hour12: false })}
          </div>
        </div>
      </div>
    </nav>
  );
}

// ── TopBar ────────────────────────────────────────────────────────────────────

function TopBar({ activePage }) {
  const { state, actions } = useApp();
  const titles = {
    overview: 'Overview',
    alerts:   'Live Alerts',
    pods:     'Pod Security',
    metrics:  'Metrics & Observability',
    timeline: 'Attack Timeline',
    rules:    'Detection Rules',
  };

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '14px 24px',
      background: '#0d1b2e',
      borderBottom: '1px solid #0f2a47',
      position: 'sticky', top: 0, zIndex: 10,
      flexShrink: 0,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ fontSize: 18, fontWeight: 700, color: '#e2eaf7' }}>
          {titles[activePage]}
        </div>
        {activePage === 'metrics' && (
          <span style={{ fontSize: 11, color: '#7c4dff', fontFamily: 'JetBrains Mono', fontWeight: 400 }}>
            Prometheus + Grafana
          </span>
        )}
        {state.loading && (
          <span style={{ fontSize: 10, color: '#4d7090', fontFamily: 'JetBrains Mono', animation: 'pulse 1.5s infinite' }}>
            loading…
          </span>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {state.lastSync && (
          <span style={{ fontSize: 10, color: '#2d4a60', fontFamily: "'JetBrains Mono', monospace" }}>
            synced {new Date(state.lastSync).toLocaleTimeString('en-IN', { hour12: false })}
          </span>
        )}
        <span style={{ fontSize: 12, color: '#2d4a60', fontFamily: "'JetBrains Mono', monospace" }}>
          {new Date().toLocaleDateString('en-IN')}
        </span>
        {activePage !== 'metrics' && (
          <button
            onClick={actions.clearAlerts}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 14px', borderRadius: 7, fontSize: 12,
              background: 'rgba(255,59,59,.08)', border: '1px solid rgba(255,59,59,.25)',
              color: '#ff6b6b', cursor: 'pointer',
              fontFamily: "'Syne', sans-serif", fontWeight: 500,
            }}
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="13" height="13">
              <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/>
              <path d="M10 11v6M14 11v6"/>
            </svg>
            Clear Alerts
          </button>
        )}
      </div>
    </div>
  );
}

// ── Alert-to-toast bridge ─────────────────────────────────────────────────────

function AlertToastBridge() {
  const { state } = useApp();
  const { add }   = useToast();
  const prevLen   = useRef(state.alerts.length);
  const mountedAt = useRef(Date.now());

  useEffect(() => {
    // Skip toasts on initial load (first 3 seconds) to avoid flooding on bootstrap
    if (Date.now() - mountedAt.current < 3000) {
      prevLen.current = state.alerts.length;
      return;
    }

    if (state.alerts.length > prevLen.current) {
      const newAlerts = state.alerts.slice(0, state.alerts.length - prevLen.current);
      newAlerts
        .filter(a => !a.acknowledged)
        .slice(0, 3) // max 3 toasts per batch to avoid spam
        .forEach(a => add(a));
    }
    prevLen.current = state.alerts.length;
  }, [state.alerts.length]); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}

// ── Main app shell ────────────────────────────────────────────────────────────

function AppInner() {
  const [activePage, setActivePage] = useState('overview');
  const PageComponent = PAGE_COMPONENTS[activePage];

  return (
    <div style={{
      position: 'fixed', inset: 0,
      display: 'flex', flexDirection: 'row',
      background: '#060c18', overflow: 'hidden',
    }}>
      <AlertToastBridge />
      <Sidebar activePage={activePage} setActivePage={setActivePage} />
      <div style={{
        flex: 1, display: 'flex', flexDirection: 'column',
        minWidth: 0, overflow: 'hidden', height: '100%',
      }}>
        <TopBar activePage={activePage} />
        <OfflineBanner apiUrl={CONFIG.API_URL} />
        <div style={{ flex: 1, overflow: 'hidden', minHeight: 0 }}>
          <PageComponent />
        </div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <ToastProvider>
        <AppInner />
      </ToastProvider>
    </AppProvider>
  );
}
