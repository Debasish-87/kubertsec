// config/index.js — KubeRTSec Frontend Configuration
// Reads from env variables injected at build time (REACT_APP_*) or window.__KUBERTSEC_CONFIG__

const runtimeConfig = (typeof window !== 'undefined' && window.__KUBERTSEC_CONFIG__) || {};

export const CONFIG = {
  // Backend URL — override via REACT_APP_API_URL or window.__KUBERTSEC_CONFIG__.apiUrl
  API_URL: runtimeConfig.apiUrl
    || process.env.REACT_APP_API_URL
    || 'http://localhost:8080',

  // WebSocket URL — auto-derived or override
  WS_URL: runtimeConfig.wsUrl
    || process.env.REACT_APP_WS_URL
    || (() => {
      const api = runtimeConfig.apiUrl || process.env.REACT_APP_API_URL || 'http://localhost:8080';
      return api.replace(/^http/, 'ws') + '/ws';
    })(),

  // Polling intervals (ms)
  STATS_INTERVAL:   parseInt(process.env.REACT_APP_STATS_INTERVAL   || '30000', 10),
  POD_INTERVAL:     parseInt(process.env.REACT_APP_POD_INTERVAL     || '15000', 10),
  METRICS_INTERVAL: parseInt(process.env.REACT_APP_METRICS_INTERVAL || '15000', 10),
  CHART_INTERVAL:   parseInt(process.env.REACT_APP_CHART_INTERVAL   || '3000',  10),

  // Max alerts kept in memory
  MAX_ALERTS: parseInt(process.env.REACT_APP_MAX_ALERTS || '500', 10),

  // App version (injected by CI/CD)
  VERSION: process.env.REACT_APP_VERSION || '1.0.0',
};

export default CONFIG;
