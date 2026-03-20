// store/AppStore.js — KubeRTSec Production State Management
import React, { createContext, useContext, useReducer, useEffect, useRef, useCallback } from 'react';
import { api, fetchDashboardInit } from '../services/api';
import { wsClient } from '../services/websocket';
import CONFIG from '../config';

// ── Constants ─────────────────────────────────────────────────────────────────

export const DEFAULT_RULES = [
  { name: 'suspicious_download_curl',   severity: 'high',     mode: 'alert',   process: 'curl',    message: 'External download via curl',     enabled: true },
  { name: 'suspicious_download_wget',   severity: 'high',     mode: 'alert',   process: 'wget',    message: 'External download via wget',     enabled: true },
  { name: 'reverse_shell_nc',           severity: 'critical', mode: 'enforce', process: 'nc',      message: 'Reverse shell (netcat)',          enabled: true },
  { name: 'crypto_miner_xmrig',         severity: 'critical', mode: 'enforce', process: 'xmrig',   message: 'Crypto miner detected',          enabled: true },
  { name: 'container_escape_nsenter',   severity: 'critical', mode: 'enforce', process: 'nsenter', message: 'Namespace escape attempt',        enabled: true },
  { name: 'privilege_escalation_sudo',  severity: 'high',     mode: 'alert',   process: 'sudo',    message: 'Privilege escalation via sudo',  enabled: true },
];

// ── Initial state ─────────────────────────────────────────────────────────────

const initialState = {
  // Core data
  alerts: [],
  pods: {},           // keyed by pod name
  rules: [],
  namespaces: [],
  posture: null,

  // Computed stats
  stats: {
    threats: 0, blocked: 0,
    podsTotal: 0, podsRunning: 0, podsTerminated: 0, podsFailed: 0,
    namespaceCount: 0, criticalAlerts: 0, highAlerts: 0,
    compromisedPods: 0, clusterHealth: 'OK',
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    lastHour: 0, last24h: 0,
  },

  // UI state
  wsStatus: 'disconnected',
  loading: true,
  backendOnline: null,   // null=unknown, true, false
  lastSync: null,
  errors: {},           // { alerts: Error|null, pods: Error|null, ... }

  // Chart data (ring buffer, last 30 ticks)
  chartData: Array(30).fill(0),
};

// ── Reducer ───────────────────────────────────────────────────────────────────

function reducer(state, action) {
  switch (action.type) {

    // ── Connection ──────────────────────────────────────────────────────────
    case 'WS_STATUS':
      return { ...state, wsStatus: action.payload };

    case 'BACKEND_STATUS':
      return { ...state, backendOnline: action.payload };

    case 'SET_LOADING':
      return { ...state, loading: action.payload };

    case 'SET_ERRORS':
      return { ...state, errors: { ...state.errors, ...action.payload } };

    // ── Initial data load ───────────────────────────────────────────────────
    case 'INIT_DATA': {
      const { alerts = [], pods = [], rules = [], stats = {}, posture = null } = action.payload;

      // Build pod map from K8s pods first
      const podMap = {};
      pods.forEach(p => { podMap[p.name] = normalizePod(p); });

      // Also build pods from alerts (for when K8s is unavailable)
      const normalizedAlerts = alerts.map(normalizeAlert).filter(Boolean);
      normalizedAlerts.forEach(a => {
        if (!a.pod || a.pod === 'unknown') return;
        if (!podMap[a.pod]) {
          podMap[a.pod] = {
            name: a.pod, namespace: a.namespace,
            status: 'Running', node: a.node || '',
            ip: '', ready: true, restarts: 0,
            threats: 0, processes: [], lastEvent: '',
          };
        }
        podMap[a.pod].threats   = (podMap[a.pod].threats || 0) + 1;
        podMap[a.pod].lastEvent = a.timestamp;
        podMap[a.pod].processes = [...new Set([...(podMap[a.pod].processes || []), a.process].filter(Boolean))];
      });

      const ns = [...new Set([
        ...pods.map(p => p.namespace),
        ...normalizedAlerts.map(a => a.namespace),
      ].filter(Boolean))];

      const podList = Object.values(podMap);
      const crit = normalizedAlerts.filter(a => a.severity === 'critical').length;
      const high = normalizedAlerts.filter(a => a.severity === 'high').length;

      return {
        ...state,
        alerts: normalizedAlerts,
        pods: podMap,
        rules: rules.length > 0 ? rules : DEFAULT_RULES,
        namespaces: ns,
        posture,
        stats: {
          ...mergeStats(stats, alerts, pods),
          podsTotal:       podList.length,
          podsRunning:     podList.filter(p => p.status === 'Running').length,
          podsTerminated:  podList.filter(p => ['Terminated','Completed'].includes(p.status)).length,
          podsFailed:      podList.filter(p => !['Running','Terminated','Completed'].includes(p.status)).length,
          compromisedPods: podList.filter(p => (p.threats || 0) > 0).length,
          namespaceCount:  ns.length,
          criticalAlerts:  crit,
          highAlerts:      high,
          clusterHealth:   crit > 0 ? 'CRITICAL' : high > 0 ? 'WARN' : 'OK',
        },
        chartData: buildChartFromAlerts(normalizedAlerts),
        loading: false,
        backendOnline: true,
        lastSync: new Date().toISOString(),
      };
    }

    // ── Pod sync ─────────────────────────────────────────────────────────────
    case 'POD_SYNC': {
      const incoming = action.payload || [];
      const podMap = { ...state.pods };
      const nsSet = new Set(state.namespaces);

      incoming.forEach(p => {
        nsSet.add(p.namespace);
        const existing = podMap[p.name] || {};
        podMap[p.name] = {
          threats:   existing.threats   || 0,
          processes: existing.processes || [],
          lastEvent: existing.lastEvent || '',
          ...normalizePod(p),
        };
      });

      // Mark removed pods as Terminated ONLY if K8s returned actual data
      // If incoming is empty, it means K8s is unavailable — don't wipe alert-created pods
      if (incoming.length > 0) {
        const k8sNames = new Set(incoming.map(p => p.name));
        Object.keys(podMap).forEach(name => {
          if (!k8sNames.has(name) && podMap[name].status === 'Running') {
            podMap[name] = { ...podMap[name], status: 'Terminated', ready: false };
          }
        });
      }

      const podList = Object.values(podMap);
      return {
        ...state,
        pods: podMap,
        namespaces: [...nsSet],
        lastSync: new Date().toISOString(),
        stats: {
          ...state.stats,
          podsTotal:       podList.length,
          podsRunning:     podList.filter(p => p.status === 'Running').length,
          podsTerminated:  podList.filter(p => ['Terminated', 'Completed'].includes(p.status)).length,
          podsFailed:      podList.filter(p => !['Running', 'Terminated', 'Completed'].includes(p.status)).length,
          compromisedPods: podList.filter(p => (p.threats || 0) > 0).length,
          namespaceCount:  nsSet.size,
        },
      };
    }

    // ── New alert (from WebSocket) ────────────────────────────────────────
    case 'NEW_ALERT': {
      const raw = action.payload;
      // Null payload = chart tick (keep chart moving even without events)
      if (!raw) {
        return { ...state, chartData: [...state.chartData.slice(1), 0] };
      }

      // Controller sends { type: "alert", data: {...} }
      const alertData = raw?.type === 'alert' ? raw.data : raw;
      const alert = normalizeAlert(alertData);
      if (!alert) return { ...state, chartData: [...state.chartData.slice(1), 0] };

      // Deduplicate
      if (state.alerts.some(a => a.id === alert.id)) return state;

      const newAlerts = [alert, ...state.alerts].slice(0, CONFIG.MAX_ALERTS);
      const chartData = [...state.chartData.slice(1), 1];

      // Update pod threat counts
      const pods = { ...state.pods };
      const podName = alert.pod;
      if (podName && podName !== 'unknown') {
        const existing = pods[podName] || {
          name: podName, namespace: alert.namespace,
          status: 'Running', threats: 0, processes: [], lastEvent: '',
          node: '', ip: '', ready: true, restarts: 0,
        };
        pods[podName] = {
          ...existing,
          // Keep existing K8s status if it came from real cluster, else Running
          status:    existing.status || 'Running',
          threats:   (existing.threats || 0) + 1,
          lastEvent: alert.timestamp,
          processes: [...new Set([...(existing.processes || []), alert.process].filter(Boolean))],
        };
      }

      const crit = newAlerts.filter(a => a.severity === 'critical').length;
      const high = newAlerts.filter(a => a.severity === 'high').length;

      return {
        ...state,
        alerts: newAlerts,
        pods,
        chartData,
        stats: {
          ...state.stats,
          threats:         newAlerts.length,
          blocked:         alert.killed ? state.stats.blocked + 1 : state.stats.blocked,
          criticalAlerts:  crit,
          highAlerts:      high,
          clusterHealth:   crit > 0 ? 'CRITICAL' : high > 0 ? 'WARN' : 'OK',
          compromisedPods: Object.values(pods).filter(p => (p.threats || 0) > 0).length,
        },
      };
    }

    // ── Stats refresh ─────────────────────────────────────────────────────
    case 'STATS_REFRESH': {
      const s = action.payload || {};
      return {
        ...state,
        stats: {
          ...state.stats,
          threats:        s.total              ?? state.stats.threats,
          blocked:        s.killed             ?? state.stats.blocked,
          criticalAlerts: s.by_severity?.critical ?? state.stats.criticalAlerts,
          highAlerts:     s.by_severity?.high      ?? state.stats.highAlerts,
          lastHour:       s.last_hour          ?? state.stats.lastHour,
          last24h:        s.last_24h           ?? state.stats.last24h,
          bySeverity:     s.by_severity || state.stats.bySeverity,
          clusterHealth: (s.by_severity?.critical ?? state.stats.criticalAlerts) > 0
            ? 'CRITICAL'
            : (s.by_severity?.high ?? state.stats.highAlerts) > 0
            ? 'WARN' : 'OK',
        },
      };
    }

    // ── WebSocket init event (recent 20 alerts sent on connect) ──────────
    case 'WS_INIT': {
      const incoming = (action.payload || []).map(normalizeAlert).filter(Boolean);
      if (incoming.length === 0) return state;

      // Merge without duplicating
      const existingIds = new Set(state.alerts.map(a => a.id));
      const newOnes = incoming.filter(a => !existingIds.has(a.id));
      if (newOnes.length === 0) return state;

      const merged = [...newOnes, ...state.alerts].slice(0, CONFIG.MAX_ALERTS);

      // Rebuild pods from all merged alerts (K8s may be unavailable)
      const pods = { ...state.pods };
      newOnes.forEach(a => {
        if (!a.pod || a.pod === 'unknown') return;
        if (!pods[a.pod]) {
          pods[a.pod] = {
            name: a.pod, namespace: a.namespace,
            status: 'Running', node: a.node || '',
            ip: '', ready: true, restarts: 0,
            threats: 0, processes: [], lastEvent: '',
          };
        }
        pods[a.pod].threats   = (pods[a.pod].threats || 0) + 1;
        pods[a.pod].lastEvent = a.timestamp;
        pods[a.pod].processes = [...new Set([...(pods[a.pod].processes || []), a.process].filter(Boolean))];
      });

      const podList = Object.values(pods);
      const nsSet   = new Set([...state.namespaces, ...newOnes.map(a => a.namespace).filter(Boolean)]);
      const crit    = merged.filter(a => a.severity === 'critical').length;
      const high    = merged.filter(a => a.severity === 'high').length;

      return {
        ...state,
        alerts: merged,
        pods,
        namespaces: [...nsSet],
        chartData: buildChartFromAlerts(merged),
        stats: {
          ...state.stats,
          threats:         merged.length,
          podsTotal:       podList.length,
          podsRunning:     podList.filter(p => p.status === 'Running').length,
          compromisedPods: podList.filter(p => (p.threats || 0) > 0).length,
          namespaceCount:  nsSet.size,
          criticalAlerts:  crit,
          highAlerts:      high,
          clusterHealth:   crit > 0 ? 'CRITICAL' : high > 0 ? 'WARN' : 'OK',
        },
      };
    }

    // ── Alert actions ─────────────────────────────────────────────────────
    case 'ACK_ALERT':
      return {
        ...state,
        alerts: state.alerts.map(a => a.id === action.payload ? { ...a, acknowledged: true } : a),
      };

    case 'DELETE_ALERT': {
      const remaining = state.alerts.filter(a => a.id !== action.payload);
      const crit = remaining.filter(a => a.severity === 'critical').length;
      const high = remaining.filter(a => a.severity === 'high').length;
      return {
        ...state,
        alerts: remaining,
        stats: {
          ...state.stats,
          threats:       remaining.length,
          criticalAlerts: crit,
          highAlerts:     high,
          clusterHealth:  crit > 0 ? 'CRITICAL' : high > 0 ? 'WARN' : 'OK',
        },
      };
    }

    // ── Rules ────────────────────────────────────────────────────────────
    case 'SET_RULES':
      return { ...state, rules: action.payload };

    case 'TOGGLE_RULE':
      return {
        ...state,
        rules: state.rules.map(r =>
          r.name === action.payload ? { ...r, enabled: !r.enabled } : r
        ),
      };

    // ── Posture ──────────────────────────────────────────────────────────
    case 'POSTURE_UPDATE':
      return { ...state, posture: action.payload };

    // ── Clear ────────────────────────────────────────────────────────────
    case 'CLEAR_ALERTS':
      return {
        ...state,
        alerts: [],
        chartData: Array(30).fill(0),
        stats: {
          ...state.stats,
          threats: 0, blocked: 0, criticalAlerts: 0,
          highAlerts: 0, clusterHealth: 'OK', lastHour: 0,
        },
      };

    default:
      return state;
  }
}

// ── Context ───────────────────────────────────────────────────────────────────

const AppContext = createContext(null);

export function AppProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const statsTickRef   = useRef(null);
  const podTickRef     = useRef(null);
  const chartTickRef   = useRef(null);
  const abortRef       = useRef(null);

  // ── Initial data load + background polling ─────────────────────────────

  useEffect(() => {
    const ac = new AbortController();
    abortRef.current = ac;

    // 1. Connect WebSocket
    wsClient._destroyed = false;
    wsClient.connect();

    const unsubMsg = wsClient.onMessage(data => {
      if (data?.type === 'init') {
        dispatch({ type: 'WS_INIT', payload: data.data });
      } else if (data?.type === 'alert') {
        dispatch({ type: 'NEW_ALERT', payload: data });
      } else {
        dispatch({ type: 'NEW_ALERT', payload: data });
      }
    });

    const unsubStatus = wsClient.onStatus(status => {
      dispatch({ type: 'WS_STATUS', payload: status });
    });

    // 2. Bootstrap REST fetch
    (async () => {
      try {
        const init = await fetchDashboardInit(ac.signal);
        if (!ac.signal.aborted) {
          dispatch({ type: 'INIT_DATA', payload: init });
          if (Object.values(init.errors).some(Boolean)) {
            dispatch({ type: 'SET_ERRORS', payload: init.errors });
          }
        }
      } catch (err) {
        if (err.name === 'AbortError') return;
        console.warn('[AppStore] bootstrap failed:', err);
        dispatch({ type: 'SET_LOADING', payload: false });
        dispatch({ type: 'BACKEND_STATUS', payload: false });
      }
    })();

    // 3. Chart tick — keeps graph moving
    chartTickRef.current = setInterval(() => {
      dispatch({ type: 'NEW_ALERT', payload: null });
    }, CONFIG.CHART_INTERVAL);

    // 4. Stats polling
    statsTickRef.current = setInterval(async () => {
      try {
        const stats = await api.alerts.stats(ac.signal);
        if (stats) dispatch({ type: 'STATS_REFRESH', payload: stats });
      } catch {}
    }, CONFIG.STATS_INTERVAL);

    // 5. Pod sync polling
    podTickRef.current = setInterval(async () => {
      try {
        const pods = await api.pods.list('', ac.signal);
        if (pods) dispatch({ type: 'POD_SYNC', payload: pods });
      } catch {}
    }, CONFIG.POD_INTERVAL);

    return () => {
      ac.abort();
      unsubMsg();
      unsubStatus();
      wsClient.disconnect();
      // eslint-disable-next-line react-hooks/exhaustive-deps
      clearInterval(chartTickRef.current);
      // eslint-disable-next-line react-hooks/exhaustive-deps
      clearInterval(statsTickRef.current);
      // eslint-disable-next-line react-hooks/exhaustive-deps
      clearInterval(podTickRef.current);
    };
  }, []);

  // ── Actions ────────────────────────────────────────────────────────────

  const actions = {
    acknowledgeAlert: useCallback(async (id) => {
      try {
        await api.alerts.acknowledge(id);
        dispatch({ type: 'ACK_ALERT', payload: id });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err };
      }
    }, []),

    deleteAlert: useCallback(async (id) => {
      try {
        await api.alerts.delete(id);
        dispatch({ type: 'DELETE_ALERT', payload: id });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err };
      }
    }, []),

    reloadRules: useCallback(async () => {
      try {
        const result = await api.rules.reload();
        // Refresh rules list after reload
        const rules = await api.rules.list();
        if (rules) dispatch({ type: 'SET_RULES', payload: rules });
        return { ok: true, result };
      } catch (err) {
        return { ok: false, error: err };
      }
    }, []),

    toggleRule: useCallback((name) => {
      dispatch({ type: 'TOGGLE_RULE', payload: name });
    }, []),

    clearAlerts: useCallback(() => {
      dispatch({ type: 'CLEAR_ALERTS' });
    }, []),

    reconnectWS: useCallback(() => {
      wsClient.forceReconnect();
    }, []),

    refreshPosture: useCallback(async () => {
      try {
        const posture = await api.posture.get();
        if (posture) dispatch({ type: 'POSTURE_UPDATE', payload: posture });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err };
      }
    }, []),
  };

  return (
    <AppContext.Provider value={{ state, dispatch, actions }}>
      {children}
    </AppContext.Provider>
  );
}

export const useApp = () => {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used inside AppProvider');
  return ctx;
};

// ── Normalizers ───────────────────────────────────────────────────────────────

export function normalizeAlert(raw) {
  if (!raw) return null;
  // Skip protocol messages
  if (raw.type === 'init' || raw.type === 'pod_sync') return null;

  const alertData = raw.type === 'alert' ? raw.data : raw;
  if (!alertData) return null;

  return {
    id:           alertData.id            || `ws-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    timestamp:    alertData.timestamp     || new Date().toISOString(),
    rule:         alertData.rule_name     || alertData.rule || alertData.type || 'unknown',
    severity:     (alertData.severity     || 'info').toLowerCase(),
    pod:          alertData.pod           || 'unknown',
    namespace:    alertData.namespace     || 'default',
    process:      alertData.process       || '?',
    args:         alertData.args          || '',
    message:      alertData.message       || `Security event: ${alertData.rule_name || 'unknown'}`,
    node:         alertData.node          || '',
    pid:          alertData.pid           || 0,
    uid:          alertData.uid           || 0,
    ip:           alertData.ip            || '',
    port:         alertData.port          || 0,
    killed:       alertData.killed        || false,
    acknowledged: alertData.acknowledged  || false,
    processTree:  alertData.process_tree  || [],
    containerID:  alertData.container_id  || '',
    image:        alertData.image         || '',
  };
}

export function normalizePod(raw) {
  return {
    name:      raw.name       || 'unknown',
    namespace: raw.namespace  || 'default',
    status:    raw.status     || 'Unknown',
    node:      raw.node       || '',
    ip:        raw.ip         || '',
    ready:     raw.ready      ?? false,
    restarts:  raw.restarts   || 0,
    threats:   raw.threats    || 0,
    processes: raw.processes  || [],
    lastEvent: raw.lastEvent  || '',
  };
}

function mergeStats(apiStats, alerts, pods) {
  const bySev = apiStats?.by_severity || {};
  const crit = bySev.critical ?? alerts.filter(a => (a.severity || '').toLowerCase() === 'critical').length;
  const high = bySev.high     ?? alerts.filter(a => (a.severity || '').toLowerCase() === 'high').length;
  return {
    threats:         apiStats?.total          ?? alerts.length,
    blocked:         apiStats?.killed         ?? 0,
    podsTotal:       pods.length,
    podsRunning:     pods.filter(p => p.status === 'Running').length,
    podsTerminated:  pods.filter(p => ['Terminated', 'Completed'].includes(p.status)).length,
    podsFailed:      pods.filter(p => !['Running', 'Terminated', 'Completed'].includes(p.status)).length,
    namespaceCount:  [...new Set(pods.map(p => p.namespace))].length,
    criticalAlerts:  crit,
    highAlerts:      high,
    compromisedPods: 0,
    clusterHealth:   crit > 0 ? 'CRITICAL' : high > 0 ? 'WARN' : 'OK',
    bySeverity:      bySev,
    lastHour:        apiStats?.last_hour ?? 0,
    last24h:         apiStats?.last_24h  ?? 0,
  };
}

function buildChartFromAlerts(alerts) {
  const chart = Array(30).fill(0);
  const now = Date.now();
  const bucket = 30000; // 30s buckets
  alerts.forEach(a => {
    const age = now - new Date(a.timestamp).getTime();
    const i = Math.floor(age / bucket);
    if (i >= 0 && i < 30) chart[29 - i]++;
  });
  return chart;
}
