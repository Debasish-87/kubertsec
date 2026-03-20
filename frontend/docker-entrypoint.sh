#!/bin/sh
# docker-entrypoint.sh — inject runtime config into nginx + JS bundle

set -e

# ── 1. Nginx config: substitute CONTROLLER_URL ───────────────────────────────
CONTROLLER_URL="${CONTROLLER_URL:-http://controller:8080}"
export CONTROLLER_URL

envsubst '${CONTROLLER_URL}' \
  < /etc/nginx/nginx.conf.template \
  > /etc/nginx/nginx.conf

echo "[entrypoint] nginx proxying to: ${CONTROLLER_URL}"

# ── 2. Runtime JS config injection ───────────────────────────────────────────
# If REACT_APP_API_URL was not set at build time, we inject it at runtime
# via window.__KUBERTSEC_CONFIG__ in index.html.
#
# This lets the same Docker image run against different backends without rebuild.
API_URL="${REACT_APP_API_URL:-}"
WS_URL="${REACT_APP_WS_URL:-}"

if [ -n "$API_URL" ] || [ -n "$WS_URL" ]; then
  RUNTIME_CONFIG="<script>window.__KUBERTSEC_CONFIG__={apiUrl:'${API_URL}',wsUrl:'${WS_URL}'};</script>"
  # Inject before </head>
  sed -i "s|</head>|${RUNTIME_CONFIG}</head>|" /usr/share/nginx/html/index.html
  echo "[entrypoint] injected runtime config: apiUrl=${API_URL} wsUrl=${WS_URL}"
else
  echo "[entrypoint] using build-time config (no runtime override)"
fi

# ── 3. Start nginx ─────────────────────────────────────────────────────────────
exec "$@"
