// services/websocket.js — KubeRTSec Production WebSocket Client
import CONFIG from '../config';

const WS_URL = CONFIG.WS_URL;

export class WSClient {
  constructor() {
    this.ws = null;
    this.messageListeners = new Set();
    this.statusListeners = new Set();
    this.reconnectTimer = null;
    this.pingTimer = null;
    this.retries = 0;
    this.maxRetries = 0; // 0 = unlimited
    this.status = 'disconnected';
    this._destroyed = false;
  }

  // ── Public API ────────────────────────────────────────────────────────────

  connect() {
    if (this._destroyed) return;
    if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) return;
    clearTimeout(this.reconnectTimer);
    this._setStatus('connecting');

    try {
      this.ws = new WebSocket(WS_URL);

      this.ws.onopen = () => {
        this.retries = 0;
        this._setStatus('connected');
        this._startPing();
        console.info('[WS] Connected to', WS_URL);
      };

      this.ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          // Controller sends: {type: "init", data: [...]} or {type: "alert", data: {...}}
          this.messageListeners.forEach(cb => {
            try { cb(data); } catch (err) { console.error('[WS] listener error:', err); }
          });
        } catch (err) {
          console.warn('[WS] failed to parse message:', err);
        }
      };

      this.ws.onclose = (event) => {
        this._stopPing();
        if (this._destroyed) return;

        const wasConnected = this.status === 'connected';
        this._setStatus('disconnected');

        if (wasConnected) {
          console.info(`[WS] Disconnected (code=${event.code}), retrying...`);
        }

        this.retries++;
        const delay = Math.min(1000 * Math.pow(1.5, Math.min(this.retries - 1, 10)), 30000);
        this.reconnectTimer = setTimeout(() => this.connect(), delay);
      };

      this.ws.onerror = (e) => {
        // onerror is always followed by onclose, so reconnect logic lives in onclose
        console.warn('[WS] Error event');
      };
    } catch (e) {
      console.warn('[WS] Failed to create WebSocket:', e);
      this._setStatus('error');
      this.retries++;
      const delay = Math.min(2000 * this.retries, 30000);
      this.reconnectTimer = setTimeout(() => this.connect(), delay);
    }
  }

  disconnect() {
    this._destroyed = true;
    clearTimeout(this.reconnectTimer);
    this._stopPing();
    if (this.ws) {
      this.ws.onclose = null; // prevent reconnect on deliberate close
      this.ws.close(1000, 'client disconnect');
      this.ws = null;
    }
    this._setStatus('disconnected');
  }

  forceReconnect() {
    this._destroyed = false;
    this.retries = 0;
    clearTimeout(this.reconnectTimer);
    this._stopPing();
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
      this.ws = null;
    }
    this.connect();
  }

  /** Subscribe to messages. Returns unsubscribe function. */
  onMessage(cb) {
    this.messageListeners.add(cb);
    return () => this.messageListeners.delete(cb);
  }

  /** Subscribe to status changes. Returns unsubscribe function. */
  onStatus(cb) {
    this.statusListeners.add(cb);
    return () => this.statusListeners.delete(cb);
  }

  getStatus() { return this.status; }
  isConnected() { return this.status === 'connected'; }

  // ── Private ───────────────────────────────────────────────────────────────

  _setStatus(status) {
    if (this.status === status) return;
    this.status = status;
    this.statusListeners.forEach(cb => { try { cb(status); } catch {} });
  }

  _startPing() {
    this._stopPing();
    // Backend handles pings; we just keep the connection alive on the JS side
    this.pingTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        // WebSocket ping frames are handled by browser; nothing needed here
        // But we check readyState so we can detect silent drops
      } else {
        this._stopPing();
      }
    }, 30000);
  }

  _stopPing() {
    clearInterval(this.pingTimer);
    this.pingTimer = null;
  }
}

// Singleton
export const wsClient = new WSClient();
export default wsClient;
