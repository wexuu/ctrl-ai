# Running the ctrl-ai gateway

The gateway is the LiteLLM proxy from a pinned Docker image with the ctrl-ai hooks, on `http://localhost:4000`, bound to 127.0.0.1 only, with no database. [ARCHITECTURE.md](ARCHITECTURE.md) describes what it does with each request.

## Prerequisites

- Docker with Compose v2.24 or newer, and the daemon running.
- The image `ghcr.io/berriai/litellm:v1.103.2` (about 1.2 GB). `make up` pulls it if it is missing. Do not change the tag: nothing older than 1.103.1 is safe to run.
- `make`, `bash`, `curl`, and Python 3.13 as `python3` (for `make setup` and the test suite).
- Claude Code, only for `make claude-env` and `make live-check`.

Never `pip install litellm` on the host. LiteLLM runs only from the pinned image.

## First-time setup

```
cp .env.example .env
echo "sk-ctrl-ai-$(openssl rand -hex 24)"     # put this in .env as LITELLM_MASTER_KEY
make setup                               # creates .venv and installs the package with its extras
```

`.env` is never committed. `LITELLM_MASTER_KEY` is the only required value; compose refuses to start without it, because LiteLLM with no master key accepts unauthenticated requests.

A variable exported in your shell overrides the same variable in `.env`.

## Start and stop

```
make up        # starts the gateway, the admin app, Redis and the telemetry services; waits until healthy
make smoke     # health and auth checks; makes no model call
make down      # stops it
```

`make help` lists every target.

## Two ways to reach a model

One config serves both. Which one applies depends only on what the client sends.

| Mode | Use it when | What you need |
|---|---|---|
| **Subscription pass-through** (default) | You use Claude Code signed in with your own Claude subscription, on your own machine. | Nothing beyond the gateway key. Leave `ANTHROPIC_API_KEY` empty in `.env`. |
| **Provider key** | Any other client, or there is no subscription login. | An Anthropic Console API key in `.env` as `ANTHROPIC_API_KEY`. |

In subscription mode Claude Code sends its own login token; the gateway forwards it and never stores or logs it. The gateway cannot make model calls of its own in this mode.

## Pointing Claude Code at the gateway

```
make claude-env             # subscription mode
make claude-env MODE=key    # provider-key mode
```

This prints the `export` and `unset` lines; it does not run them. Paste them into the shell you start Claude Code from, or run `eval "$(make -s claude-env)"`. The output contains the gateway key, so do not paste it anywhere else.

In subscription mode `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_API_KEY` must not be set: either one replaces the subscription login for that traffic.

To check the whole path with one real turn:

```
make live-check                             # normal prompt, then a prompt that must be blocked
LIVE_CHECK_EXPECT_BLOCK=0 make live-check   # normal prompt only (infra-only config)
```

It uses your Claude subscription for one or two short prompts.

## Logs

- **Gateway logs:** `make logs`. At the default level they hold request lines and errors, no prompt text and no keys. Do not turn on LiteLLM's debug logging: in pass-through mode it may print request headers.
- **Audit log:** `logs/audit.jsonl`, one JSON object per line. A `decision` row per checked request and a `usage` row per finished request, joined by `request_id`, plus `tool`, `shadow`, `incident` and `break_glass` rows. It never holds prompt text, header values or keys ([GATEWAY.md](GATEWAY.md)).

```
tail -f logs/audit.jsonl
tail -n 20 logs/audit.jsonl | jq -c '{type, decision, rule, status, jev: .jev.status}'
```

## Admin panel and dashboard

`make up` also starts the admin app on `http://localhost:4100` (`make ui-open` prints the URL, `make ui-logs` follows its log). It binds to 127.0.0.1 unless `CTRL_AI_UI_BIND` says otherwise. It has no sign-in (see [ADMIN.md](ADMIN.md)), so keep it on a trusted network. Its pages:

| Page | What it shows or edits |
|---|---|
| `/dashboard` (also `/`) | Management (spend, budgets, forecast, adoption), Security & compliance (blocks, findings, masking, reroutes, semantic scores, tools, break-glass) and Operations (latency, errors, fallbacks, outages), with period and team filters and an auditor export |
| `/audit` | The audit log, newest request first; click a row for its decision and usage rows |
| `/jev-trust` | The classifier and the second model on live traffic and the offline audit report ([XAI.md](XAI.md)) |
| `/admin/policy` | The policy: profiles, rules, packs, thresholds; a rule tester |
| `/admin/security` | Prompt-injection safeguards, personal-data protection, loop caps and timeouts, break-glass settings |
| `/admin/models` | The model catalogue: approved, trial, banned models, prices, fallbacks |
| `/admin/teams` | Departments, teams, budgets, gateway keys, break-glass overrides, the semantic-outage switch |
| `/admin/tools` | Approved MCP servers and tools, pin status, re-pinning a reviewed description |
| `/admin/history` | Every saved version of each configuration file, with diffs and rollback |

Every change is validated, versioned and written to the admin audit log (`logs/admin.jsonl`).

## Running with a configuration profile

`make up PROFILE=bank` starts the gateway and the admin app on the bank demo profile in `config/profiles/bank/` instead of the example organisation in `config/` ([CONFIGURATION.md](CONFIGURATION.md)).

## Running without paid keys

- **Keyless test stack.** `make test-up` runs the gateway against stub Anthropic and Jev servers with fake keys from `tests/e2e/test.env`; nothing leaves the machine ([TESTING.md](TESTING.md)).
- **Decision models.** Set `CTRL_AI_CLASSIFIER_MODEL=none` to run without Jev, and point the judge at a local OpenAI-compatible server ([MODELS.md](MODELS.md)). The deterministic checks run either way.
- **Claude Code on a subscription.** Subscription pass-through needs no provider key (below).

## Running without the guardrail

`deploy/litellm/config.infra-only.yaml` is the same gateway with no guardrail and no logger. Use it to tell a gateway problem from a guardrail problem:

```
CTRL_AI_GATEWAY_CONFIG=/app/gateway/config.infra-only.yaml make up
```

Nothing is checked or audited in this mode.

## Troubleshooting

- **The container exits with code 3 and `ModuleNotFoundError`** (for example `No module named 'ctrl_ai'`, followed by `ImportError: Could not import ctrl_ai_logger from ctrl_ai.adapters.litellm.logger`): a mount or `PYTHONPATH` is missing. Check that `docker compose config` shows `src/ctrl_ai` mounted at `/app/ctrl_ai` with `PYTHONPATH: /app`.
- **`401 Invalid or revoked ctrl-ai key`**: the gateway key is wrong, revoked, expired or missing. In subscription mode this usually means `ANTHROPIC_CUSTOM_HEADERS` is not set in the shell Claude Code runs in. Keys are issued on the Teams page and stored as hashes in `state/keys.json`.
- **`Invalid model name`**: the `claude-*` wildcard entry is missing from the config. Claude Code asks for whatever model its user has selected.
- **`HEAD /api/hello` answered 404 in the gateway log**: harmless. Claude Code probes for it.
- **Files in `logs/` owned by root**: the container created them. Use `make up`, which creates `logs/audit.jsonl` as your user first.
- **`required variable LITELLM_MASTER_KEY is missing a value`**: there is no `.env`, or the key is not set in it.
- **A refused-key line in the gateway log after `make smoke`**: expected; the smoke check sends a request without a key and one with a wrong key on purpose.
- **Empty folders named `state`, `logs` or `config` appear in the repo**: Docker creates a missing bind-mount source as root. `make up` creates them as your user first; remove the root-owned ones with `sudo rm -r` and run `make up` again.
- **Port 4000 is already in use**: another gateway is running. `docker ps` shows it; `make down` in that checkout stops it. To run a second stack beside it, set `CTRL_AI_GATEWAY_PORT` and `CTRL_AI_UI_PORT`.
- **`make up` times out waiting for health**: `make logs` shows why. Do not probe `GET /health`: it makes a real model call for every configured model.
