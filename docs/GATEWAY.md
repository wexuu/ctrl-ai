# The gateway: request path, controls, audit rows

How the gateway decides about each request, which settings drive each control, and what the audit rows hold. [ARCHITECTURE.md](ARCHITECTURE.md) gives the overview; this page is the reference. Code: `src/ctrl_ai/pipeline/engine.py` runs the steps, `src/ctrl_ai/adapters/litellm/` connects them to LiteLLM. Configuration: `config/*.yaml` ([CONFIGURATION.md](CONFIGURATION.md)); runtime state: `state/keys.json`, `state/break_glass.json`.

## Request path

```
custom auth      adapters/litellm/auth.py        gateway key → identity (team, department, user, key id,
                                                 profile, mode); master key → admin identity;
                                                 route = claude_subscription when Authorization carries a
                                                 Claude subscription token (prefix check only), else external
pre_call         adapters/litellm/guardrail.py → hooks.before_call → Engine.pre_call     may change the request
  extract        newest turn → pieces: prompt, tool_result, tool_call (system prompts never);
                 Claude Code's leading <system-reminder> blocks become reminder pieces
  profile        the identity's profile and mode from the policy; session id; route
  break-glass    a valid x-ctrl-ai-break-glass token relaxes the controls it names
  detect         pipeline/detectors.py: normalisation (tag characters decoded, hidden characters removed
                 and counted, NFKC), policy rules, then the packs (pii, pl, secrets, signatures)
  evaluate       pipeline/evaluator.py: block or flag from the findings and the mode; masking plan
                 (external route: rewrite; subscription: semantic copy only); governance (catalogue,
                 team, data class → allow / reroute / 403)
  outage         manual switch, or both semantic circuits open → degrade (flag) / fail_closed (503)
  loop caps      Redis counters → warn / throttle 429 / stop 429; the agent timeout caps the model call
  budget         reserve an estimate → ok / near / exceeded → downgrade (reroute) / 429 / alert only
  rewrite        pipeline/effects.py: external route, personal data replaced by surrogates (fail closed: 503)
  refuse now (the decision row is written), or keep the context for the semantic hook
during_call      adapters/litellm/semantic.py → hooks.during_call → Engine.semantic_call   alongside the model
  classifier     per source (prompt, tool_result), behind its circuit breaker
  judge          when the classifier rejects, is unsure or is unavailable, behind its circuit breaker
  decide         the profile: observe / flag / block (400); the decision row is written
post_call        adapters/litellm/restore.py      surrogates → real values in answers and tool-call arguments
logger           adapters/litellm/logger.py → hooks.after_call    usage row; session tokens; budget reconcile;
                                                 the decision row (semantic.reason "not_run") if the semantic
                                                 hook never ran
MCP              adapters/litellm/mcp.py          before a tool call: approved server, team, tool, pinned
                                                 description, deterministic checks on the arguments;
                                                 after it: deterministic checks on the result; one tool row
```

Unexpected errors in ctrl-ai's own code fail open (the request is allowed and the row carries `error: "internal: <Class>"`), except masking on the external route, which fails closed by default (`masking.on_error`).

## Controls and their settings

| Control | Settings | Notes |
|---|---|---|
| Profiles | `profiles`, `default_profile`; a team's `profile` and `mode` in `teams.yaml` | `mode` (enforce / monitor), `semantic_action`, `on_semantic_unavailable`. A global `mode: monitor` turns the whole organisation to observe-only |
| Rules and packs | `rules`, `rule_packs` | Packs `pii`, `pl`, `secrets`, `signatures` ([CONFIGURATION.md](CONFIGURATION.md)). A `rules:` entry with a pack rule's id overrides its action, sources, severity and enabled flag. Card numbers, IBANs and the Polish identifiers are checksum-validated |
| Signatures | `config/signatures.yaml` | Each entry has a source and a match / near-miss pair that the unit tests run |
| Normalisation | `normalisation.hidden_char_threshold` | Only the checked copy is normalised; the request goes on unchanged |
| Claude Code reminders | – | Split off only for Claude Code (User-Agent `claude-cli/` or `x-app: cli`) and only from the leading text; checked by the secrets and signatures packs, never sent to the semantic check |
| Identity | `state/keys.json` (hashes) | The master key is the admin identity (`team: admin`). A wrong, revoked or expired key gets 401 |
| Governance | `config/models.yaml` | Order: not in the catalogue → banned → deprecated → team not allowed → data class. Masked data does not count toward the data class. A subscription request is only routed to `claude-*` models |
| Pricing | catalogue `price` | `cost_source`: catalogue, litellm, unknown; `shadow` marks free-tier list prices |
| Semantic check | `jev`, `judge`; `CTRL_AI_*_MODEL` | Classifier below `jev.accept_below` → accepted; otherwise the judge decides, rejecting from `judge.reject_from`. Without `accept_below`: the judge is asked in the uncertain band `review_threshold` ≤ score < `block_threshold` and when the classifier is unavailable ([MODELS.md](MODELS.md)) |
| Model fallbacks | `router_settings.fallbacks` in `deploy/litellm/config.yaml` | Read at start-up only: restart the gateway after changing a chain; the gateway warns at start-up when they differ from the catalogue |
| Loop caps | `loops` | Session = `x-claude-code-session-id`, else LiteLLM's session id, else the key and a 10-minute bucket |
| Budgets | a team's `budget` | The reservation is atomic in Redis; the master key has no budget |
| Masking | `masking`, `CTRL_AI_MASKING_SECRET` | Without a secret masking is off and rows say `masking: no_secret` |
| Semantic outage | `semantic_outage` | One circuit per component (`jev`, `judge`); the manual switch on the Teams page or `scripts/break-glass.py outage` |
| Break-glass | `break_glass`, `CTRL_AI_BREAKGLASS_SECRET` | `scripts/break-glass.py issue|revoke|list`; rules in `never_relax` are never relaxed, not even through a relaxed pack |
| MCP tools | `config/mcp.yaml` | Approved servers, teams, allowed tools, pinned description hashes |

## Audit rows (v2)

`logs/audit.jsonl` (`CTRL_AI_AUDIT_LOG`), one JSON object per line, never prompt text, response text, keys, tokens or header values. The row builders are `src/ctrl_ai/core/rows.py`, `src/ctrl_ai/governance/usage.py`, `src/ctrl_ai/mcp/core.py`, `src/ctrl_ai/semantic/outage.py` and `src/ctrl_ai/semantic/shadow.py`.

| `type` | Written | Main fields |
|---|---|---|
| `decision` | once per checked request | identity (`team`, `department`, `user`, `key_id`, `profile`), `mode`, `decision`, `would_block`, `rule`, `findings` (rule, pack, source, action, severity), `data_class_detected`, `normalisation`, `masked` (counts), `model_requested`, `model_routed`, `route_reason`, `jev`, `judge`, `semantic`, `flagged`, `loop`, `budget`, `break_glass`, `policy_version`, `text_chars`, `guard_ms`; when they say something: `masking`, `restore`, `mask_store`, `identity_error`, `error` |
| `usage` | once per finished model call | `status`, `input_tokens`, `output_tokens`, `cost_usd`, `cost_source`, `price_known`, `shadow`, `provider`, `fallback_used`, `total_ms`, `error`, identity and model fields |
| `tool` | once per MCP tool call | `server`, `tool`, `team`, `decision`, `findings`, `description_pinned`, `latency_ms`, `reason`, `error` |
| `shadow` | once per shadow check | `jev_score`, `second` (the sampled probability and how it came about), `agree`, `possible_miss` |
| `incident` | on circuit and outage transitions | `event`, `component`, `mode`, `reason` |
| `break_glass` | on issue, use, revoke, expire | `event`, `id`, `subject`, `relax`, `ticket`, `issued_by`, `expires_at` |

Rule ids that are not pack or policy rules: `model-not-approved`, `model-banned`, `model-deprecated`, `model-team-not-allowed`, `model-data-class`, `budget-exceeded`, `masking-failed`, `semantic-outage`, `hidden-characters`. A request that fell back to another model has two usage rows under one id: a failure with 0 tokens, then a success with `fallback_used: true`.

## How the gateway uses LiteLLM

Design notes on LiteLLM v1.103.2, the pinned version.

- **Custom auth and subscription pass-through.** `general_settings.custom_auth` receives the key from `x-litellm-api-key` when present (it wins over `Authorization`), so a Claude subscription token in `Authorization` is never taken for the gateway key and is still forwarded upstream. The master key works as `Authorization: Bearer`, `x-api-key` and `x-litellm-api-key`. `/health/liveliness` needs no key.
- **Route detection.** Inside the pre-call hook the `Authorization` value in `proxy_server_request.headers` is already masked, so the route is decided in custom auth (prefix check only) and passed on in `user_api_key_dict.metadata["ctrl_ai_route"]`. Custom headers such as `x-ctrl-ai-break-glass` and `x-claude-code-session-id` reach the hook unmasked.
- **Rerouting.** Setting `data["model"]` in the pre-call hook sends the request to that model's deployment on `/v1/messages`, `/v1/chat/completions` and `/v1/responses`; the usage row's `model_group` is the new model.
- **The semantic hook** (`async_moderation_hook`, mode `during_call`) runs on all three endpoints in parallel with the upstream call, so a 1 s model and a 1 s classifier take about 1 s in total. A block there happens after the upstream call was made.
- **Fallbacks.** The standard logging object has no fallback field; LiteLLM logs the failed attempt and then the success (with the fallback's `model_group`) under the same call id. LiteLLM also falls back on a 400.
- **Headers on a refusal.** A guardrail's `HTTPException(headers=...)` loses its headers; `ProxyException(headers=...)` keeps them, so a 429 carries `Retry-After`.

[LIMITATIONS.md](LIMITATIONS.md) lists what the gateway does not cover.
