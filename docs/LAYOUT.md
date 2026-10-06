# Repository layout

```
src/ctrl_ai/              the installable package (pip install -e ".[admin,dev]")
  core/                   request context, policy loading, file stores, schema validation, audit rows and log, Redis state
  detect/                 extraction of the checked turn, normalisation, detectors, rule packs, signatures, masking and restore
  semantic/               the semantic decision: decision models (models.py: Jev, LiteLLM, static), Jev client (jev/),
                          the judge prompt, shadow sampling, circuit breakers, outage mode
  governance/             identity and teams, model governance and catalogue, budgets, loop caps, break-glass, routes, usage rows
  pipeline/               the engine that runs the steps above for one request, hook glue and the per-request context cache
  mcp/                    MCP tool checks: approved servers, pinned tool descriptions, content checks
  adapters/litellm/       every LiteLLM hook (guardrail, semantic, restore, MCP, logger, auth); the only code that imports LiteLLM
  evaluation/             offline audit of the semantic models: metrics, reviewers, labels, drift monitor, report
  admin/                  the admin panel and dashboard (FastAPI), static/ for the pages
config/                   policy, teams, models, MCP servers, signature feed for an example organisation
  schema/                 the JSON Schemas of those files
  profiles/               alternative configurations (bank/: the bank demo profile); docs/CONFIGURATION.md
deploy/
  docker/                 Dockerfiles, compose.yml and the compose.test.yml overlay for the keyless test stack
  litellm/                the LiteLLM proxy configurations (full, degraded lane, infra-only)
  k8s/                    Kustomize base and overlays (local, aws)
  otel/                   OpenTelemetry collector and Prometheus configuration
  lane/                   policy of the degraded lane
datasets/                 synthetic casebook and fixtures for the offline audit
docs/                     this documentation
scripts/                  operator scripts: break-glass, smoke checks, Claude Code environment, offline audit worker
tests/
  unit/                   mirrors src/ctrl_ai (core, detect, semantic, governance, pipeline, adapters, mcp, evaluation, admin)
  e2e/                    end-to-end tests against the keyless test stack; runtime/ is created at test time
  stubs/                  stub Anthropic, Jev and MCP servers used by the test stack
  fixtures/               sample audit rows, Jev responses and config/, the frozen configuration every test runs against
  policy/                 policy regression cases: a request in, the expected decision out
```

Runtime files stay out of the repository: `.env` (keys), `state/` (gateway keys, break-glass register, config history), `logs/` (audit and admin logs) and `reports/` are git-ignored.
