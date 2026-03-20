// components/Toast.jsx — KubeRTSec Live Alert Toast Notifications
import React, { createContext, useContext, useReducer, useCallback, useEffect, useRef } from 'react';

// ── Context ───────────────────────────────────────────────────────────────────

const ToastContext = createContext(null);

const SEV_STYLE = {
  critical: { border: '#ff3b3b', icon: '🔴', label: 'CRITICAL', bar: '#ff3b3b' },
  high:     { border: '#ff8c42', icon: '🟠', label: 'HIGH',     bar: '#ff8c42' },
  medium:   { border: '#ffd166', icon: '🟡', label: 'MEDIUM',   bar: '#ffd166' },
  low:      { border: '#4db8ff', icon: '🔵', label: 'LOW',      bar: '#4db8ff' },
  info:     { border: '#4db8ff', icon: '🔵', label: 'INFO',     bar: '#4db8ff' },
};

function reducer(state, action) {
  switch (action.type) {
    case 'ADD':
      return [action.payload, ...state].slice(0, 5); // max 5 visible
    case 'REMOVE':
      return state.filter(t => t.id !== action.id);
    case 'CLEAR':
      return [];
    default:
      return state;
  }
}

// ── Provider ──────────────────────────────────────────────────────────────────

export function ToastProvider({ children }) {
  const [toasts, dispatch] = useReducer(reducer, []);

  const add = useCallback((alert) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const sev = (alert.severity || 'info').toLowerCase();
    const duration = sev === 'critical' ? 8000 : sev === 'high' ? 6000 : 4000;
    dispatch({ type: 'ADD', payload: { id, alert, sev, duration, ts: Date.now() } });
    return id;
  }, []);

  const remove = useCallback((id) => {
    dispatch({ type: 'REMOVE', id });
  }, []);

  return (
    <ToastContext.Provider value={{ toasts, add, remove }}>
      {children}
      <ToastContainer toasts={toasts} remove={remove} />
    </ToastContext.Provider>
  );
}

export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be inside ToastProvider');
  return ctx;
};

// ── Single Toast ───────────────────────────────────────────────────────────────

function Toast({ toast, remove }) {
  const { id, alert, sev, duration } = toast;
  const style = SEV_STYLE[sev] || SEV_STYLE.info;
  const progressRef = useRef(null);
  const timerRef    = useRef(null);
  const startRef    = useRef(Date.now());
  const [paused, setPaused] = React.useState(false);
  const [visible, setVisible] = React.useState(false);

  // Entrance animation
  useEffect(() => {
    requestAnimationFrame(() => setVisible(true));
  }, []);

  // Auto-dismiss with progress bar
  useEffect(() => {
    if (paused) {
      clearTimeout(timerRef.current);
      return;
    }

    const remaining = duration - (Date.now() - startRef.current);
    timerRef.current = setTimeout(() => {
      setVisible(false);
      setTimeout(() => remove(id), 300);
    }, Math.max(remaining, 0));

    // Animate progress bar
    if (progressRef.current) {
      progressRef.current.style.transition = `width ${remaining}ms linear`;
      requestAnimationFrame(() => {
        if (progressRef.current) progressRef.current.style.width = '0%';
      });
    }

    return () => clearTimeout(timerRef.current);
  }, [paused, id, duration, remove]);

  const handlePause = () => {
    setPaused(true);
    startRef.current = Date.now() - (duration - (timerRef.current ? duration : 0));
    if (progressRef.current) {
      const w = progressRef.current.getBoundingClientRect().width;
      const parentW = progressRef.current.parentElement?.getBoundingClientRect().width || 1;
      progressRef.current.style.transition = 'none';
      progressRef.current.style.width = `${(w / parentW) * 100}%`;
    }
  };

  const handleResume = () => {
    startRef.current = Date.now();
    setPaused(false);
  };

  return (
    <div
      onMouseEnter={handlePause}
      onMouseLeave={handleResume}
      style={{
        position: 'relative',
        background: '#0d1b2e',
        border: `1px solid ${style.border}40`,
        borderLeft: `3px solid ${style.border}`,
        borderRadius: 8,
        padding: '10px 12px',
        minWidth: 280,
        maxWidth: 360,
        boxShadow: `0 4px 20px rgba(0,0,0,.5), 0 0 0 1px ${style.border}15`,
        cursor: 'pointer',
        overflow: 'hidden',
        transform: visible ? 'translateX(0) scale(1)' : 'translateX(20px) scale(0.97)',
        opacity: visible ? 1 : 0,
        transition: 'transform 0.25s cubic-bezier(.22,.68,0,1.2), opacity 0.25s ease',
        animation: sev === 'critical' ? 'criticalPulse 2s ease infinite' : 'none',
      }}
      onClick={() => { setVisible(false); setTimeout(() => remove(id), 300); }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
        <span style={{ fontSize: 12 }}>{style.icon}</span>
        <span style={{
          fontSize: 9, fontWeight: 700, color: style.border,
          fontFamily: "'JetBrains Mono', monospace", letterSpacing: '1px',
        }}>
          {style.label}
        </span>
        <span style={{ fontSize: 9, color: '#2d4a60', fontFamily: "'JetBrains Mono', monospace", marginLeft: 'auto' }}>
          {new Date(alert.timestamp).toLocaleTimeString('en-IN', { hour12: false })}
        </span>
        <span style={{ fontSize: 12, color: '#2d4060', lineHeight: 1 }}>×</span>
      </div>

      {/* Message */}
      <div style={{
        fontSize: 11, color: '#c0d0e0', fontWeight: 500,
        marginBottom: 5, lineHeight: 1.4,
        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
      }}>
        {alert.message}
      </div>

      {/* Meta */}
      <div style={{
        display: 'flex', gap: 8,
        fontSize: 9, color: '#4d7090',
        fontFamily: "'JetBrains Mono', monospace",
      }}>
        <span style={{ color: '#00e5ff' }}>{alert.process}</span>
        <span>›</span>
        <span style={{
          maxWidth: 140, overflow: 'hidden',
          textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {alert.pod}
        </span>
        {alert.killed && (
          <span style={{
            marginLeft: 'auto', color: '#ff3b3b', fontWeight: 700,
            background: 'rgba(255,59,59,.12)', padding: '1px 5px', borderRadius: 3,
          }}>KILLED</span>
        )}
      </div>

      {/* Progress bar */}
      <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 2, background: 'rgba(255,255,255,.05)' }}>
        <div
          ref={progressRef}
          style={{ height: '100%', width: '100%', background: style.bar, borderRadius: 1 }}
        />
      </div>
    </div>
  );
}

// ── Container ─────────────────────────────────────────────────────────────────

function ToastContainer({ toasts, remove }) {
  if (toasts.length === 0) return null;
  return (
    <div style={{
      position: 'fixed',
      bottom: 20,
      right: 20,
      zIndex: 9999,
      display: 'flex',
      flexDirection: 'column-reverse',
      gap: 8,
      pointerEvents: 'none',
    }}>
      {toasts.map(t => (
        <div key={t.id} style={{ pointerEvents: 'all' }}>
          <Toast toast={t} remove={remove} />
        </div>
      ))}
    </div>
  );
}
