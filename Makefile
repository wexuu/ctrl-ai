# ctrl-ai: development and operations targets. `make help` lists them.

PYTHON ?= python3
MODE ?= subscription
COMPOSE := docker compose --project-directory . -f deploy/docker/compose.yml
UI_URL := http://localhost:4100

# Degraded lane (compose profile "lane").
OVERLAY ?= local
CTRL_AI_LANE_PORT ?= 4050
LANE_PROJECT ?= ctrl-ai-lane

# Configuration profile: `make up PROFILE=bank` points the gateway and the admin panel at
# config/profiles/bank/; a file the profile does not have comes from config/.
PROFILE ?=
profile_file = $(if $(wildcard config/profiles/$(PROFILE)/$(1).yaml),/app/config/profiles/$(PROFILE)/$(1).yaml,/app/config/$(1).yaml)
PROFILE_ENV := $(if $(PROFILE),CTRL_AI_POLICY_FILE=$(call profile_file,policy) CTRL_AI_TEAMS_FILE=$(call profile_file,teams) \
	CTRL_AI_MODELS_FILE=$(call profile_file,models) CTRL_AI_MCP_FILE=$(call profile_file,mcp),)

# The admin container writes files in this checkout (config/, state/, logs/, or tests/e2e/runtime/
# for the test stack), so it runs as the invoking user. A value on the command line or in the
# environment wins; for `make up` a CTRL_AI_UID / CTRL_AI_GID set in .env wins over the default.
CTRL_AI_UID ?= $(shell id -u)
CTRL_AI_GID ?= $(shell id -g)
export CTRL_AI_UID CTRL_AI_GID
# Compose prefers the shell environment to .env, so `make up` passes the .env values on again
# when the ids above are only the defaults.
DOTENV_IDS := $(if $(filter file,$(origin CTRL_AI_UID)),$(shell sed -n 's/^\(CTRL_AI_[UG]ID=[0-9][0-9]*\)[[:space:]]*$$/\1/p' .env 2>/dev/null))

# Test stack. Project name and ports can be changed so two stacks run side by side:
#   make test CTRL_AI_TEST_PROJECT=ctrl-ai-a CTRL_AI_GATEWAY_PORT=4200 CTRL_AI_UI_PORT=4300 CTRL_AI_STUB_ANTHROPIC_PORT=9201 CTRL_AI_STUB_JEV_PORT=9202
CTRL_AI_TEST_PROJECT ?= ctrl-ai-test
CTRL_AI_GATEWAY_PORT ?= 4000
CTRL_AI_UI_PORT ?= 4100
CTRL_AI_STUB_ANTHROPIC_PORT ?= 9001
CTRL_AI_STUB_JEV_PORT ?= 9002
export CTRL_AI_TEST_PROJECT CTRL_AI_GATEWAY_PORT CTRL_AI_UI_PORT CTRL_AI_STUB_ANTHROPIC_PORT CTRL_AI_STUB_JEV_PORT
export CTRL_AI_TEST_BASE_URL ?= http://localhost:$(CTRL_AI_GATEWAY_PORT)
export CTRL_AI_TEST_UI_URL ?= http://localhost:$(CTRL_AI_UI_PORT)
export CTRL_AI_TEST_STUB_ANTHROPIC_URL ?= http://localhost:$(CTRL_AI_STUB_ANTHROPIC_PORT)
export CTRL_AI_TEST_STUB_JEV_URL ?= http://localhost:$(CTRL_AI_STUB_JEV_PORT)

# Shell variables would override --env-file, so the ones that could point a test run at a real
# service or key are removed from the environment of every test compose command.
TEST_COMPOSE := env -u LITELLM_MASTER_KEY -u ANTHROPIC_API_KEY -u ANTHROPIC_API_BASE -u JEV_API_KEY -u JEV_URL \
	-u GROQ_API_KEY -u MISTRAL_API_KEY -u CTRL_AI_BREAKGLASS_SECRET -u CTRL_AI_MASKING_SECRET -u CTRL_AI_ADMIN_PASSWORD \
	$(COMPOSE) -p $(CTRL_AI_TEST_PROJECT) --env-file tests/e2e/test.env -f deploy/docker/compose.test.yml

.DEFAULT_GOAL := help

.PHONY: help setup lint format up down logs smoke claude-env live-check ui-open ui-logs break-glass jev-check bench \
	test test-unit test-e2e test-up test-down test-live k8s-render k8s-validate lane-up lane-down \
	xai-audit xai-replay xai-report xai-review-sheet xai-import-labels

# ---------------------------------------------------------------- development

setup: ## Create .venv and install the package with its admin and dev extras
	@test -d .venv || $(PYTHON) -m venv .venv
	@.venv/bin/python -m pip install --quiet --upgrade pip
	.venv/bin/python -m pip install --quiet -e ".[admin,dev]"

lint: ## Ruff (lint and format check) and pyright
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .
	.venv/bin/pyright

format: ## Reformat and fix what ruff can fix
	.venv/bin/ruff check --fix .
	.venv/bin/ruff format .

test-unit: ## Unit tests and policy regression cases
	.venv/bin/python -m pytest tests/unit tests/policy -q

test-up: ## Start the keyless test stack (gateway, admin panel, stubs)
	.venv/bin/python tests/e2e/prepare_runtime.py
	$(TEST_COMPOSE) up -d --wait

test-down: ## Stop the test stack
	$(TEST_COMPOSE) down

test-e2e: ## End-to-end tests against the running test stack
	.venv/bin/python -m pytest tests/e2e -q

# The stack is stopped whatever happens, and the exit status is the tests' (or test-up's).
test: test-unit ## Unit tests, then the test stack and end-to-end tests
	$(MAKE) test-up && $(MAKE) test-e2e; status=$$?; $(MAKE) test-down; exit $$status

test-live: ## Live checks with real credentials (needs make up)
	.venv/bin/python -m pytest tests/e2e/live -m live -q

# ---------------------------------------------------------------- running

up: ## Start the gateway with .env and wait until it is healthy (PROFILE=bank: a configuration profile)
	@test -f .env || { echo "No .env file. Run: cp .env.example .env, then set LITELLM_MASTER_KEY." >&2; exit 1; }
	@# The container runs as root: create the audit file first so the host user owns it.
	@mkdir -p logs && touch logs/audit.jsonl
	@mkdir -p state/history && test -f state/keys.json || echo '{"keys": []}' > state/keys.json
	@test -f state/break_glass.json || echo '{"overrides": []}' > state/break_glass.json
	@touch logs/admin.jsonl
	$(PROFILE_ENV) $(DOTENV_IDS) $(COMPOSE) up -d --wait

down: ## Stop the gateway
	$(COMPOSE) down

logs: ## Follow the gateway's logs
	$(COMPOSE) logs -f gateway

ui-open: ## Print the admin panel's URL (started by make up)
	@echo "Admin panel: $(UI_URL)"

ui-logs: ## Follow the admin panel's logs
	$(COMPOSE) logs -f ui

smoke: ## Health and auth checks against the running gateway
	@scripts/smoke.sh

claude-env: ## Print the shell lines that point Claude Code at the gateway (MODE=subscription|key)
	@MODE=$(MODE) scripts/claude-env.sh

live-check: ## One real Claude Code turn through the gateway (MODE=subscription|key)
	@MODE=$(MODE) scripts/live-check.sh

break-glass: ## Break-glass for security on-call: make break-glass ARGS="issue|revoke|list|outage ..."
	@set -a; [ -f .env ] && . ./.env; set +a; .venv/bin/python scripts/break-glass.py $(ARGS)

bench: ## Time the request path (pre-call and full decision) on the frozen test configuration
	.venv/bin/python scripts/bench_precall.py $(if $(ITERATIONS),--iterations $(ITERATIONS),)

jev-check: ## Print a real Jev verdict for TEXT="..." using JEV_API_KEY from .env
	@set -a; [ -f .env ] && . ./.env; set +a; .venv/bin/python -m ctrl_ai.semantic.jev "$(TEXT)"

# ---------------------------------------------------------------- deployment

k8s-render: ## Render the Kubernetes manifests (OVERLAY=local|aws) to stdout
	@test "$(OVERLAY)" != local || test -f deploy/k8s/overlays/local/secrets.env || \
		cp deploy/k8s/overlays/local/secrets.env.example deploy/k8s/overlays/local/secrets.env
	@kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/k8s/overlays/$(OVERLAY)

# `kubectl apply --dry-run=client` still needs a cluster for API discovery, so without one the
# check is: both overlays render, every object has apiVersion, kind and metadata.name.
k8s-validate: ## Render both overlays and check every object (no cluster needed)
	@dir=$$(mktemp -d); for o in local aws; do \
		$(MAKE) --no-print-directory k8s-render OVERLAY=$$o > $$dir/$$o.yaml || exit 1; \
		echo "$$o: $$(grep -c '^kind:' $$dir/$$o.yaml) objects rendered"; \
		.venv/bin/python -c "import sys, yaml; docs=[d for d in yaml.safe_load_all(open(sys.argv[1])) if d]; bad=[d for d in docs if not (d.get('apiVersion') and d.get('kind') and d.get('metadata', {}).get('name'))]; print('  ' + ', '.join(sorted({d['kind'] for d in docs}))); sys.exit(1 if bad else 0)" $$dir/$$o.yaml || exit 1; \
	done; rm -rf $$dir

lane-up: ## Start the break-glass degraded lane on 127.0.0.1:$(CTRL_AI_LANE_PORT) (deterministic checks only)
	@mkdir -p logs && touch logs/audit.jsonl
	CTRL_AI_LANE_PORT=$(CTRL_AI_LANE_PORT) $(COMPOSE) -p $(LANE_PROJECT) --profile lane up -d --wait gateway-lane
	@echo "Degraded lane on http://localhost:$(CTRL_AI_LANE_PORT). Runbook: docs/DEPLOY.md. Stop it with make lane-down."

lane-down: ## Stop the degraded lane
	CTRL_AI_LANE_PORT=$(CTRL_AI_LANE_PORT) $(COMPOSE) -p $(LANE_PROJECT) --profile lane down

# ---------------------------------------------------------------- Jev trust audit (docs/XAI.md)
# Audit-only: none of these targets change policy or live decisions.

xai-audit: ## Score the synthetic casebook with Jev and the second model (needs JEV_API_KEY, GROQ_API_KEY; max 200 calls)
	.venv/bin/python scripts/xai_audit.py run $(if $(RECORD),--record,)

xai-replay: ## Publish the committed recorded audit run for the Jev trust page (no keys, no model calls)
	.venv/bin/python scripts/xai_audit.py replay

xai-report: ## Rebuild the report from the latest run and current labels (no model calls)
	.venv/bin/python scripts/xai_audit.py report

xai-review-sheet: ## Write a blind review sheet (no scores, no answer key) to state/xai/review/
	.venv/bin/python scripts/xai_audit.py review-sheet

xai-import-labels: ## Import a filled review sheet: make xai-import-labels FILE=path.csv
	@test -n "$(FILE)" || { echo "Usage: make xai-import-labels FILE=state/xai/review/blind_sheet.csv" >&2; exit 1; }
	.venv/bin/python scripts/xai_audit.py import-labels "$(FILE)"

help: ## List targets
	@awk -F':.*## ' '/^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
