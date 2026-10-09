# Testing

Four suites, from fast to slow. None of them needs a real key except the live checks.

| Suite | Where | Runs with | Needs |
|---|---|---|---|
| Unit tests | `tests/unit/` (mirrors `src/ctrl_ai/`) | `make test-unit` | the virtualenv (`make setup`) |
| Policy regression cases | `tests/policy/` | `make test-unit` | the virtualenv |
| End-to-end tests | `tests/e2e/` | `make test` (or `make test-up`, `make test-e2e`, `make test-down`) | Docker |
| Live checks | `tests/e2e/live/`, `scripts/live-check.sh` | `make test-live`, `make live-check` | a gateway started with `make up` and real keys in `.env` |

`make lint` runs ruff (lint and format check) and pyright; `make bench` runs the request-path benchmark ([PERFORMANCE.md](PERFORMANCE.md)).

## The frozen configuration

Every suite runs against the configuration in `tests/fixtures/config/` (policy, teams, models, MCP servers, signature feed), never against the deployable `config/`. `tests/conftest.py` points the `CTRL_AI_*_FILE` variables at it for the unit and policy tests, and `make test-up` copies it into `tests/e2e/runtime/` for the test stack. Editing `config/` therefore never changes a test result, and the tests can rely on fixture details: a `test-marker` rule on the text `CTRL-AI-BLOCK-TEST`, all four rule packs, teams on every profile. The deployable files in `config/` and `config/profiles/*/`, and the degraded lane's policy, are only checked for what they must be: they parse and match their JSON Schemas, and the teams that the catalogue and the MCP servers name exist (`tests/unit/core/test_shipped_config.py`).

## Unit tests

`.venv/bin/python -m pytest tests/unit tests/policy -q`. They need no network, no Docker and no LiteLLM: the engine is built with stand-ins (`StaticModel` for the decision models, `tests/unit/fake_state.py` for Redis), and the LiteLLM adapters are tested with fake LiteLLM modules (`tests/unit/adapters/`).

## Policy regression cases

`tests/policy/cases.yaml` lists requests and the decision each must get; `tests/policy/test_policy_regression.py` runs each through the engine with the frozen configuration. A case has:

- `name`;
- `team` (omit it for the master key) and optionally `route` (`external` or `claude_subscription`) and `model`;
- `prompt`, or `messages` for a whole conversation (tool calls and tool results included);
- `jev` and `judge`: the stub scores (a number, or `unavailable`); the defaults are 0.02 and 0.05;
- `expect`: fields of the decision row, dotted for nested ones (`semantic.action`), plus `finding_rules` (the sorted rule ids of the findings) and `message` (the refusal text, or null).

To add one, append an entry and run `make test-unit`. A case that fails shows the expected and the actual fields side by side.

## End-to-end tests

`make test` runs the unit tests, starts the keyless test stack, runs `tests/e2e/` against it and stops it. The stack is `deploy/docker/compose.yml` with the overlay `deploy/docker/compose.test.yml`, under the compose project `ctrl-ai-test`, with `tests/e2e/test.env` as its only environment file (fake keys only; the `Makefile` removes real keys from the shell environment for these commands). It runs the real gateway image with the ctrl-ai hooks, the admin app, Redis and the telemetry services, plus stub servers in place of the providers:

| Stub | Port | Markers |
|---|---|---|
| Anthropic Messages API (`tests/stubs/anthropic_stub.py`) | 9001 | `UPSTREAM-400-TEST` → 400; `PROVIDER-DOWN-TEST` on `claude-opus-5-5` → 500 (fallback); `SLOW-1S-TEST` → one-second answer; judge calls answer 0.91 for `ATTACKTEST` or `JUDGE-HIGH-TEST`, else 0.05; `JUDGE-DOWN-TEST` → 500; `JUDGE-SLOW-TEST` → slow judge |
| Jev (`tests/stubs/jev_stub.py`) | 9002 | `ATTACKTEST` → 0.93; `JEV-UNCERTAIN-TEST` → 0.55; `JEV-500-TEST` → 500; `JEV-SLOW-TEST` → six-second answer; `SLOW-1S-TEST` → one second |
| MCP servers (`tests/stubs/mcp_stub.py`) | internal | a `read_page` title containing `INJECT` returns a hidden instruction (`TAGS` hides it in Unicode tag characters); `MCP_STUB_RUGPULL=1` changes a tool description |

The stubs record what they received (lengths, ids and flags, never text) at `/_stub/requests`, so the tests can check what reached the provider, for example that masked identifiers did not. The gateway listens on 4000 and the admin app on 4100. Every prompt the suite sends carries a unique tag, and the last test (`test_zz_no_secrets.py`) checks that no prompt, key or token reached the audit log.

### Next to a running gateway

The test stack uses its own compose project, but by default the same host ports as `make up`. To run it beside a running gateway, give it another project name and other ports:

```
make test CTRL_AI_TEST_PROJECT=ctrl-ai-b CTRL_AI_GATEWAY_PORT=4200 CTRL_AI_UI_PORT=4300 \
  CTRL_AI_STUB_ANTHROPIC_PORT=9201 CTRL_AI_STUB_JEV_PORT=9202
```

`make test-up` refuses to start when one of its ports is taken. `tests/e2e/runtime/` (git-ignored) holds the stack's configuration copies, state and audit log while it runs. `make test-up` creates those files as you and runs the admin container as you (`id -u`, `id -g`, passed as `CTRL_AI_UID` / `CTRL_AI_GID`), so the admin panel can write them; the test stack ignores any ids set in `.env`.

## Live checks

`make test-live` runs `tests/e2e/live/` against a gateway started with `make up`, with the real keys in `.env`; the tests are marked `live` and excluded from every other run. `make live-check` sends one real Claude Code turn through the gateway and, unless `LIVE_CHECK_EXPECT_BLOCK=0`, one that must be refused. Both use real model calls.

## Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull request: ruff, the format check, pyright and the unit and policy tests, then the end-to-end tests on the keyless stack. Locally, `pre-commit` runs ruff, the YAML and JSON checks, whitespace fixes, a private-key check (tests excluded, since the detector tests hold fake keys) and pyright before each commit.
