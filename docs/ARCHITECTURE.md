# Architecture

ctrl-ai is a security gateway for AI agents. Every agent (Claude Code, Codex, an SDK application) sends its model traffic, and optionally its MCP tool traffic, through it. The gateway checks each request, masks personal data, enforces which models a team may use and how much it may spend, stops runaway agents, and writes a content-free audit row for every decision.

## Components

```
 agents ──HTTP──► LiteLLM proxy (gateway, :4000) ──► model providers (Anthropic, Groq, Mistral, ...)
                  │  ctrl-ai hooks: custom auth, pre-call guardrail,
                  │  semantic guardrail, restore guardrail, MCP checks, logger
                  │      │
                  │      ▼
                  │  Engine (pipeline/) ── decision models: classifier (Jev), judge, shadow
                  │      │
                  ├──► Redis: loop counters, budgets, encrypted mask maps (optional; fails open)
                  ├──► logs/audit.jsonl (content-free audit rows)
                  └──► MCP servers behind the gateway
 config/*.yaml, state/*.json ◄── admin app (:4100): admin panel, dashboard, audit page, Jev trust page
```

- **The gateway** is the LiteLLM proxy from a pinned image (`ghcr.io/berriai/litellm:v1.103.2`), configured by `deploy/litellm/config.yaml`. LiteLLM handles the provider protocols, routing, fallbacks and streaming; ctrl-ai plugs in through LiteLLM's extension points, all in `src/ctrl_ai/adapters/litellm/`: custom auth (`auth.py`), three guardrails (`guardrail.py` pre-call, `semantic.py` during-call, `restore.py` post-call), the MCP guardrail (`mcp.py`) and a logging callback (`logger.py`).
- **The engine** (`src/ctrl_ai/pipeline/engine.py`) holds the decision logic and every collaborator: the configuration stores, the audit log, the shared state, the decision models, the circuit breakers and the context cache. `pipeline/runtime.py` builds the one production engine from the settings (`core/settings.py`); the adapters call `get_engine()`.
- **The admin app** (`src/ctrl_ai/admin/`, FastAPI, `:4100`) edits the configuration files and the runtime state (gateway keys, break-glass register), and reads the audit log for the dashboard ([ADMIN.md](ADMIN.md)).
- **Redis** holds the counters that several gateway replicas share: loop caps, budget reservations and the encrypted surrogate maps. Without it these fail open and the rows say `unavailable`.
- **Stubs** (`tests/stubs/`) stand in for Anthropic, Jev and two MCP servers in the keyless test stack ([TESTING.md](TESTING.md)).
- **OpenTelemetry**: the gateway exports LiteLLM's spans, without message content, to a collector and Prometheus ([OBSERVABILITY.md](OBSERVABILITY.md)).

## The request path

```
 request
   │
   ▼
 custom auth ─────────── key → identity (team, profile); route (subscription or external)     401
   │
   ▼
 pre-call (deterministic, before the model is called)
   extract     the newest turn → pieces: prompt, tool results, tool calls; Claude Code reminders apart
   profile     identity → profile and mode; session; route
   break-glass a signed override relaxes the controls it names
   detect      normalise → policy rules → packs (pii, pl, secrets, signatures)
   evaluate    block or flag from the findings; masking plan; model governance             400 / 403
   outage      semantic checks down → degrade (flag) or fail closed                         503
   loops       requests, calls per turn, identical tool calls, tokens, session length        429
   budget      reserve the estimated cost; downgrade, refuse or alert when over              429
   rewrite     external route: personal data → surrogates                                   503 if it fails
   │
   ▼
 model call ═══════════════ during-call, in parallel: classifier → judge → profile decision  400
   │
   ▼
 post-call   restore the real values in the answer (external route)
   │
   ▼
 logger      usage row; session tokens; budget reconciliation
```

The pre-call half runs before the model is called and may change the request (rerouting, masking, the agent timeout) or refuse it. The engine splits it into three kinds of step: detectors find things and decide nothing (`pipeline/detectors.py`), the evaluator turns findings, profile and shared state into the decision (`pipeline/evaluator.py`), and effects change the request (`pipeline/effects.py`). The semantic half runs alongside the model call, so its latency hides behind the model's; a refusal there means the model was called but its answer is withheld. The hooks of one request share a `RequestContext` through an in-process cache keyed by the request id (`pipeline/ctxcache.py`). Exactly one decision row is written per request: by the pre-call hook when it refuses, by the semantic hook otherwise, or by the logger when the semantic hook never ran. Writing it drops the request's text from the context; what stays in the cache for the restore hook and the logger is the decision, the counts and the surrogate map. [GATEWAY.md](GATEWAY.md) lists every step with its settings.

MCP tool calls through the gateway take a shorter path: before the call, the server must be approved for the team, the tool allowed and its description unchanged since it was reviewed, and the arguments pass the deterministic checks; after the call, the result passes them too. One `tool` row records the outcome.

## Decision models

The semantic check uses a decision model in three roles ([MODELS.md](MODELS.md)): the **classifier** scores every request with text to check (Jev by default), the **judge** decides when the classifier rejects, is unsure or is down (a safety model through LiteLLM by default), and the **shadow** check asks again, in the background, about a sample of what the classifier accepted. Each role is configured by a model spec (`jev`, `none` or a LiteLLM model string). The classifier and the judge each sit behind a circuit breaker; when both are open, or security on-call switches it on, the semantic-outage mode applies the policy's `degrade` or `fail_closed` choice.

## Configuration and live reload

The policy, teams, model catalogue, MCP servers and signature feed are YAML files in `config/` ([CONFIGURATION.md](CONFIGURATION.md)); gateway keys and the break-glass register are JSON files in `state/`. Each is read through a store that checks the file's modification time and size on use and re-parses it when they change, so a saved change applies to the next request without a restart. A file that fails its JSON Schema or its parser is ignored and the last valid version stays in force (`last_error` says why). The admin panel validates a change against the schema and the cross-file checks before it writes the file, keeps every previous version in `state/history/`, and records the change in `logs/admin.jsonl`.

## The audit log

The gateway appends one JSON object per line to `logs/audit.jsonl`: a `decision` row and a `usage` row per request, `tool` rows for MCP calls, `shadow`, `incident` and `break_glass` rows. Rows hold identifiers, labels, counts, scores and timings, never prompt or response text, keys, tokens or header values. The dashboard and the audit page read this file; in a cluster it goes to stdout for the log agent ([DEPLOY.md](DEPLOY.md)).

## Layering

```
core  ←  detect, semantic, governance  ←  pipeline  ←  adapters, admin
```

`core/` (request context, policy, stores, schemas, rows, settings, shared state) depends on nothing else in the package. `detect/`, `semantic/` and `governance/` depend on `core/` only. `pipeline/` composes them. `mcp/` stands alone. `adapters/litellm/` and `admin/` sit on top; `evaluation/` is the offline audit and imports nothing from the gateway. The adapters are the only code that imports LiteLLM's proxy; the one other LiteLLM import is the completion call of the LiteLLM-backed decision model (`semantic/models.py`), made in-process and imported where it is used, so the package installs and its tests run on a host without LiteLLM.
