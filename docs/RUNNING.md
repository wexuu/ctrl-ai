# Running the ctrl-ai gateway

The gateway is the LiteLLM proxy from a pinned Docker image, on `http://localhost:4000`, bound to 127.0.0.1 only, with no database.

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
make up        # starts the gateway and waits until it is healthy (about 10 seconds)
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
- **Audit log:** `logs/audit.jsonl`, one JSON object per line. A `decision` row per checked request and a `usage` row per finished request, joined by `request_id`. It never holds prompt text, header values or keys.

```
tail -f logs/audit.jsonl
tail -n 20 logs/audit.jsonl | jq -c '{type, decision, rule, status, jev: .jev.status}'
```

## Staging UI

`make up` also starts a small web page on `http://localhost:4100` (`make ui-open` prints the URL, `make ui-logs` follows its log). It has two halves:

- **Chat** with a free-tier model through the gateway, so the guardrail and Jev run on every message. Under each message: allowed or blocked, the rule, Jev's score, guard time, tokens and cost.
- **Log viewer**: the whole audit log (Claude Code, curl and test traffic too), newest first, with filters, totals and the current policy mode and version. Click a row for the full record.

The chat cannot use the Claude subscription. It uses `chat-mistral` or `chat-groq`, which need a free API key in `.env` (`MISTRAL_API_KEY`, `GROQ_API_KEY`); a model without a key is hidden. `CTRL_AI_UI_MODELS` picks which of them the page offers. Messages go to that provider unmasked and may be used for training: never type real data. The page keeps the chat only in the browser; the UI writes nothing to disk, and the master key never reaches the browser.

## Running without the guardrail

`deploy/litellm/config.infra-only.yaml` is the same gateway with no guardrail and no logger. Use it to tell a gateway problem from a guardrail problem:

```
CTRL_AI_GATEWAY_CONFIG=/app/gateway/config.infra-only.yaml make up
```

Nothing is checked or audited in this mode.

## Troubleshooting

- **The container exits with code 3 and `ModuleNotFoundError`** (for example `No module named 'ctrl_ai'`, followed by `ImportError: Could not import ctrl_ai_logger from ctrl_ai.adapters.litellm.logger`): a mount or `PYTHONPATH` is missing. Check that `docker compose config` shows `src/ctrl_ai` mounted at `/app/ctrl_ai` with `PYTHONPATH: /app`.
- **`400 No connected db.`**: the gateway key is wrong or missing from the request. With no database LiteLLM tries to look an unknown key up as a database key. In subscription mode this means `ANTHROPIC_CUSTOM_HEADERS` is not set in the shell Claude Code runs in. A request with no key at all gets 401.
- **`Invalid model name`**: the `claude-*` wildcard entry is missing from the config. Claude Code asks for whatever model its user has selected.
- **`HEAD /api/hello` answered 404 in the gateway log**: harmless. Claude Code probes for it.
- **Files in `logs/` owned by root**: the container created them. Use `make up`, which creates `logs/audit.jsonl` as your user first.
- **`required variable LITELLM_MASTER_KEY is missing a value`**: there is no `.env`, or the key is not set in it.
- **A traceback with `No api key passed in.` in the gateway log**: LiteLLM logs every unauthenticated request this way. `make smoke` sends one on purpose.
- **Empty folders named `state`, `logs` or `config` appear in the repo**: Docker creates a missing bind-mount source as root. `make up` creates them as your user first; remove the root-owned ones with `sudo rm -r` and run `make up` again.
- **Port 4000 is already in use**: another gateway is running. `docker ps` shows it; `make down` in that checkout stops it.
- **`make up` times out waiting for health**: `make logs` shows why. Do not probe `GET /health`: it makes a real model call for every configured model.
