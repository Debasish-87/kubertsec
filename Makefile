# KubeRTSec Makefile — Production Kubernetes Runtime Security
SHELL        := /bin/bash
.DEFAULT_GOAL := help

VERSION       := 1.0.0
GO            := go
GOFLAGS       := -trimpath
LDFLAGS       := -s -w -X main.version=$(VERSION)
BACKEND_DIR   := backend
FRONTEND_DIR  := frontend
BPF_SRC       := $(BACKEND_DIR)/bpf/execve.bpf.c
BPF_OBJ       := $(BACKEND_DIR)/bpf/execve.bpf.o
REGISTRY      ?= ghcr.io/debasish-87

-include .env
export

STORE_PATH            ?= /tmp/kubertsec-dev.db
RULES_PATH            ?= configs/rules/process_rules.yaml
ALLOWLIST_PATH        ?= configs/allowlist.yaml
RESPONSE_MODE         ?= alert
LISTEN_ADDR           ?= :8080
KUBESHIELD_CONTROLLER ?= http://localhost:8080/event
PROMETHEUS_URL        ?= http://host.docker.internal:9090
GRAFANA_URL           ?= http://host.docker.internal:3001
GRAFANA_PUBLIC_URL    ?= http://localhost:3001
GRAFANA_USER          ?= admin
GRAFANA_PASSWORD      ?= admin
GRAFANA_TOKEN         ?=

.PHONY: help setup-k8s dev dev-stop pf-start pf-stop \
        controller agent frontend build bpf \
        docker-build docker-push test lint fmt vet \
        status attack-test clean

# ── Help ────────────────────────────────────────────────────────────────────────
help:
	@printf "\n  \033[1mKubeRTSec v$(VERSION)\033[0m — Kubernetes Runtime Security\n\n"
	@printf "  \033[33m⚡ Quick Start (first time):\033[0m\n"
	@printf "    make setup-k8s      connect to your K8s cluster + port-forwards\n"
	@printf "    make dev            start all services (dashboard + controller)\n\n"
	@printf "  \033[33mDevelopment:\033[0m\n"
	@printf "    make pf-start       restart port-forwards (prometheus + grafana)\n"
	@printf "    make pf-stop        stop port-forwards\n"
	@printf "    make dev-stop       stop all docker services\n\n"
	@printf "  \033[33mBuild:\033[0m\n"
	@printf "    make build          compile Go binaries\n"
	@printf "    make docker-build   build Docker images\n"
	@printf "    make test           run Go tests\n"
	@printf "    make status         check controller health + K8s pods\n\n"

# ── K8s Setup (run once before make dev) ───────────────────────────────────────
setup-k8s: .env
	@chmod +x scripts/setup-k8s.sh
	@bash scripts/setup-k8s.sh

# ── Dev Stack ──────────────────────────────────────────────────────────────────
.env:
	@cp .env.example .env
	@echo "✓ Created .env from .env.example"

dev: .env
	@echo ""
	@echo "  \033[1mKubeRTSec Starting...\033[0m"
	@echo "  Dashboard  → http://localhost:3000"
	@echo "  Controller → http://localhost:8080"
	@echo "  Prometheus → http://localhost:9090"
	@echo "  Grafana    → http://localhost:3001"
	@echo ""
	@# Check port-forwards are active
	@if ! curl -sf http://localhost:9090/-/healthy >/dev/null 2>&1; then \
		echo "  \033[33m⚠ Prometheus port-forward not active — run: make setup-k8s\033[0m"; \
	fi
	@if ! curl -sf http://localhost:3001/api/health >/dev/null 2>&1; then \
		echo "  \033[33m⚠ Grafana port-forward not active — run: make setup-k8s\033[0m"; \
	fi
	@echo ""
	docker compose up --build

dev-stop:
	docker compose down

# ── Port-forwards (real K8s Prometheus + Grafana) ─────────────────────────────
pf-start:
	@bash scripts/setup-k8s.sh
	@echo ""
	@echo "Port-forwards active — now restart controller:"
	@echo "  docker compose restart controller"

pf-stop:
	@pkill -f "port-forward.*prometheus" 2>/dev/null || true
	@pkill -f "port-forward.*grafana"    2>/dev/null || true
	@echo "Port-forwards stopped"

# ── Native dev (without Docker) ───────────────────────────────────────────────
controller:
	cd $(BACKEND_DIR) && \
		STORE_PATH=$(STORE_PATH) RULES_PATH=$(RULES_PATH) \
		ALLOWLIST_PATH=$(ALLOWLIST_PATH) LISTEN_ADDR=$(LISTEN_ADDR) \
		PROMETHEUS_URL=$(PROMETHEUS_URL) GRAFANA_URL=$(GRAFANA_URL) \
		GRAFANA_PUBLIC_URL=$(GRAFANA_PUBLIC_URL) \
		GRAFANA_USER=$(GRAFANA_USER) GRAFANA_PASSWORD=$(GRAFANA_PASSWORD) \
		GRAFANA_TOKEN=$(GRAFANA_TOKEN) \
		$(GO) run ./cmd/controller

agent:
	cd $(BACKEND_DIR) && sudo -E \
		KUBECONFIG=$(HOME)/.kube/config \
		RESPONSE_MODE=$(RESPONSE_MODE) \
		RULES_PATH=$(PWD)/configs/rules/process_rules.yaml \
		ALLOWLIST_PATH=$(PWD)/configs/allowlist.yaml \
		KUBESHIELD_CONTROLLER=$(KUBESHIELD_CONTROLLER) \
		$(GO) run ./cmd/agent

frontend:
	cd $(FRONTEND_DIR) && \
		REACT_APP_API_URL=http://localhost:8080 \
		npm start

# ── Build ─────────────────────────────────────────────────────────────────────
bpf: $(BPF_OBJ)
$(BPF_OBJ): $(BPF_SRC)
	@which clang >/dev/null 2>&1 || (echo "ERROR: clang not found" && exit 1)
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/bpf -c $(BPF_SRC) -o $(BPF_OBJ)

build:
	@mkdir -p bin
	cd $(BACKEND_DIR) && $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ../bin/agent      ./cmd/agent
	cd $(BACKEND_DIR) && $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ../bin/controller ./cmd/controller
	@echo "✓ bin/agent  bin/controller"

docker-build:
	docker build -f $(BACKEND_DIR)/Dockerfile.controller --build-arg VERSION=$(VERSION) \
		-t $(REGISTRY)/kubertsec-controller:$(VERSION) -t $(REGISTRY)/kubertsec-controller:latest $(BACKEND_DIR)
	docker build -f $(FRONTEND_DIR)/Dockerfile --build-arg VERSION=$(VERSION) \
		-t $(REGISTRY)/kubertsec-frontend:$(VERSION) -t $(REGISTRY)/kubertsec-frontend:latest $(FRONTEND_DIR)

docker-push: docker-build
	docker push $(REGISTRY)/kubertsec-controller:$(VERSION)
	docker push $(REGISTRY)/kubertsec-controller:latest
	docker push $(REGISTRY)/kubertsec-frontend:$(VERSION)
	docker push $(REGISTRY)/kubertsec-frontend:latest

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
	cd $(BACKEND_DIR) && $(GO) test ./... -count=1 -race -timeout 60s

fmt:
	cd $(BACKEND_DIR) && $(GO) fmt ./...

vet:
	cd $(BACKEND_DIR) && $(GO) vet ./...

lint:
	cd $(BACKEND_DIR) && golangci-lint run ./... 2>/dev/null || echo "golangci-lint not installed"

# ── Status ────────────────────────────────────────────────────────────────────
status:
	@echo "── Controller ──────────────────────────────────────────"
	@curl -sf http://localhost:8080/healthz && echo " ✓ online" || echo "✗ offline"
	@echo ""
	@curl -sf http://localhost:8080/api/v1/status | python3 -m json.tool 2>/dev/null || true
	@echo "── K8s Pods ────────────────────────────────────────────"
	@kubectl get pods -A 2>/dev/null || echo "(kubectl unavailable)"

attack-test:
	@bash attack-test/attack-test.sh

clean:
	rm -rf bin/ $(BPF_OBJ) kubeconfig-docker
