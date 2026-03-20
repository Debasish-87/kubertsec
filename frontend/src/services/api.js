// services/api.js — KubeRTSec Production API Client
import CONFIG from '../config';

const BASE = CONFIG.API_URL;

// ── Error class ───────────────────────────────────────────────────────────────

export class APIError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.body = body;
  }
}

// ── Core fetch ───────────────────────────────────────────────────────────────

async function apiFetch(path, options = {}, signal) {
  const url = `${BASE}${path}`;
  try {
    const res = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...options.headers },
      signal,
      ...options,
    });

    if (!res.ok) {
      let body = null;
      try { body = await res.json(); } catch {}
      throw new APIError(body?.error || `HTTP ${res.status}`, res.status, body);
    }

    const ct = res.headers.get('Content-Type') || '';
    if (!ct.includes('application/json') || res.status === 204) return null;
    return await res.json();
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    if (err instanceof APIError) throw err;
    throw new APIError(err.message || 'Network error', 0, null);
  }
}

// ── Alerts ────────────────────────────────────────────────────────────────────

export const alertsAPI = {
  list(params = {}, signal) {
    const q = new URLSearchParams();
    if (params.limit     != null) q.set('limit',         String(params.limit));
    if (params.offset    != null) q.set('offset',        String(params.offset));
    if (params.severity)          q.set('severity',      params.severity);
    if (params.namespace)         q.set('namespace',     params.namespace);
    if (params.pod)               q.set('pod',           params.pod);
    if (params.rule_name)         q.set('rule_name',     params.rule_name);
    if (params.process)           q.set('process',       params.process);
    if (params.since)             q.set('since',         params.since);
    if (params.until)             q.set('until',         params.until);
    if (params.acknowledged != null) q.set('acknowledged', String(params.acknowledged));
    return apiFetch(`/api/v1/alerts?${q.toString()}`, {}, signal);
  },
  stats(signal)    { return apiFetch('/api/v1/alerts/stats', {}, signal); },
  get(id, signal)  { return apiFetch(`/api/v1/alerts/${id}`, {}, signal); },
  acknowledge(id)  { return apiFetch(`/api/v1/alerts/${id}/ack`, { method: 'PUT' }); },
  delete(id)       { return apiFetch(`/api/v1/alerts/${id}`, { method: 'DELETE' }); },
};

// ── Rules ─────────────────────────────────────────────────────────────────────

export const rulesAPI = {
  list(signal)    { return apiFetch('/api/v1/rules', {}, signal); },
  reload()        { return apiFetch('/api/v1/rules/reload', { method: 'POST' }); },
  get(name, signal) { return apiFetch(`/api/v1/rules/${encodeURIComponent(name)}`, {}, signal); },
  create(rule)    { return apiFetch('/api/v1/rules', { method: 'POST', body: JSON.stringify(rule) }); },
  delete(name)    { return apiFetch(`/api/v1/rules/${encodeURIComponent(name)}`, { method: 'DELETE' }); },
};

// ── Pods ─────────────────────────────────────────────────────────────────────

export const podsAPI = {
  list(namespace = '', signal) {
    const q = namespace ? `?namespace=${encodeURIComponent(namespace)}` : '';
    return apiFetch(`/api/v1/pods${q}`, {}, signal);
  },
};

// ── Posture ───────────────────────────────────────────────────────────────────

export const postureAPI = {
  async get(signal) {
    try {
      return await apiFetch('/api/v1/posture', {}, signal);
    } catch (err) {
      if (err.status === 503) return null; // not yet available
      throw err;
    }
  },
};

// ── Status ────────────────────────────────────────────────────────────────────

export const statusAPI = {
  get(signal) { return apiFetch('/api/v1/status', {}, signal); },
  async health() {
    try {
      const res = await fetch(`${BASE}/healthz`);
      return res.ok;
    } catch { return false; }
  },
};

// ── Metrics ───────────────────────────────────────────────────────────────────

export const metricsAPI = {
  cluster(query = '', signal) {
    const q = query ? `?query=${encodeURIComponent(query)}` : '';
    return apiFetch(`/api/v1/metrics/cluster${q}`, {}, signal);
  },
};

// ── Bootstrap ─────────────────────────────────────────────────────────────────

export async function fetchDashboardInit(signal) {
  const settle = (p) => p.then((v) => ({ ok: true, value: v })).catch((e) => ({ ok: false, error: e }));
  const [alertsR, statsR, rulesR, podsR, postureR] = await Promise.all([
    settle(alertsAPI.list({ limit: 200 }, signal)),
    settle(alertsAPI.stats(signal)),
    settle(rulesAPI.list(signal)),
    settle(podsAPI.list('', signal)),
    settle(postureAPI.get(signal)),
  ]);
  return {
    alerts:  alertsR.ok  ? (alertsR.value?.alerts || []) : [],
    stats:   statsR.ok   ? (statsR.value || {})           : {},
    rules:   rulesR.ok   ? (rulesR.value || [])           : [],
    pods:    podsR.ok    ? (podsR.value  || [])           : [],
    posture: postureR.ok ? postureR.value                 : null,
    errors:  {
      alerts:  alertsR.ok  ? null : alertsR.error,
      rules:   rulesR.ok   ? null : rulesR.error,
      pods:    podsR.ok    ? null : podsR.error,
    },
  };
}

export const api = { alerts: alertsAPI, rules: rulesAPI, pods: podsAPI, posture: postureAPI, status: statusAPI, metrics: metricsAPI, fetchDashboardInit };
export default api;
