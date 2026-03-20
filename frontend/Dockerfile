# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install deps first (layer cache)
COPY package.json package-lock.json ./
RUN npm ci --prefer-offline --no-audit

# Copy source and build
COPY . .

# Build args become REACT_APP_* env vars at build time
ARG REACT_APP_API_URL=""
ARG REACT_APP_WS_URL=""
ARG REACT_APP_VERSION=1.0.0

RUN npm run build

# ── Stage 2: Serve ─────────────────────────────────────────────────────────────
FROM nginx:1.25-alpine

# Install envsubst (part of gettext)
RUN apk add --no-cache gettext

WORKDIR /app

# Copy built assets
COPY --from=builder /app/build /usr/share/nginx/html

# Copy nginx template
COPY nginx/nginx.conf.template /etc/nginx/nginx.conf.template

# Entrypoint: substitute CONTROLLER_URL and start nginx
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s CMD wget -qO- http://localhost:3000/ || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
