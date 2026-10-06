# ctrl-ai gateway core

How the gateway decides about each request, which policy settings drive each control, what the audit
rows mean, and what was verified about LiteLLM v1.103.2 along the way. Code: `src/ctrl_ai/`, `src/ctrl_ai/semantic/jev/`.
Configuration: `config/policy.yaml`, `config/models.yaml`, `config/teams.yaml`, `config/signatures.yaml`
(schemas in `config/schema/`), runtime state `state/keys.json`, `state/break_glass.json`.

## Request path

```
custom auth (litellm_auth.py)          key → identity (team, department, user, key id, profile);
                                       route = claude_subscription if Authorization is "Bearer sk-ant-oat…"
pre_call  (litellm_guardrail.py → hooks.before_call → engine.pre_call)        may change the request
  extract        newest turn → pieces: prompt, tool_result, tool_call (system prompts never)
  break-glass    x-ctrl-ai-break-glass header → relaxed controls
  normalise      tag characters decoded, hidden characters removed (counted), NFKC
  rules + packs  every finding: policy rules, then the packs pii, pl, secrets, signatures
  masking plan   external route: rewrite; subscription: semantic copy only
  governance     catalogue + team + data class → allow / reroute (data["model"]) / 403
  outage         both semantic circuits open, or manual switch → degrade (flag) / fail_closed (503)
  loop caps      Redis counters → warn / 429 throttle / 429 stop
  budget         reserve estimate → ok / near / exceeded → downgrade / 429 / alert
  rewrite        external route: personal data replaced by surrogates (fail closed: 503)
  refuse now (writes the decision row), or leave the context in the cache
during_call (litellm_semantic.py → hooks.during_call)                          runs alongside the model
  Jev per source (prompt, tool_result) behind its circuit breaker → judge if Jev is unavailable or
  uncertain → the profile decides (observe / flag / block 400); writes the one decision row
post_call (litellm_restore.py)       surrogates → real values in answers and tool-call arguments
logger    (litellm_logger.py → hooks.after_call)  usage row; session tokens; budget reconcile;
                                       decision row with semantic.reason "not_run" if the semantic hook never ran
```

Unexpected errors in our code fail open (allow, `error: "internal: <Class>"`), except masking on the external
route, which fails closed.

## Controls and their settings

| Control | Settings | Notes |
|---|---|---|
| Profiles | `profiles`, `default_profile`; team's `profile` in `teams.yaml` | `mode` (enforce/monitor), `semantic_action`, `on_semantic_unavailable`. Global `mode: monitor` overrides every profile (organisation-wide observe switch) |
| Rules and packs | `rules`, `rule_packs` | Packs: `pii` (`pii-email`, `pii-phone`, `pii-card`, `pii-iban`), `pl` (`pl-pesel`, `pl-nip`, `pl-account`), `secrets` (`secret-*`), `signatures` (the feed's ids); docs/CONFIGURATION.md. A `rules:` entry with a pack rule's id overrides its action, sources, severity, enabled. Card numbers, IBANs and the Polish identifiers are checksum-validated. Under 1 ms p95 for 10,000 characters |
| Signatures | `config/signatures.yaml` | Each with a source and a match / near-miss test pair run by the unit tests |
| Normalisation | `normalisation.hidden_char_threshold` | Only the checked copy is normalised |
| Claude Code reminders | – | Split off only for Claude Code (user-agent `claude-cli/` or `x-app: cli`) and only from the leading text; checked by secrets and signatures, never sent to Jev |
| Identity | `state/keys.json` (hashes) | Master key = `team: admin`, `department: platform`. Wrong / revoked / expired key → 401 |
| Governance | `config/models.yaml` | Order: not in catalogue → banned → deprecated → team not allowed → data class. Masked data does not count toward the data class. A subscription request is only routed to `claude-*` models |
| Pricing | catalogue `price` | `cost_source`: catalogue, litellm, unknown; `shadow` for free-tier list prices |
| Semantic check | `jev`, `judge` | Jev `review_threshold` ≤ score < `block_threshold` → judge (`CTRL_AI_JUDGE_MODEL`); judge's score replaces Jev's |
| Model fallbacks | `router_settings.fallbacks` in `deploy/litellm/config.yaml` | Read at start-up only: **restart the gateway after changing a chain**; the gateway warns at start-up when they differ from the catalogue |
| Loop caps | `loops` | Session = `x-claude-code-session-id`, else LiteLLM session id, else key + 10-minute bucket |
| Budgets | team `budget` | Reservation is atomic; master key has no budget |
| Masking | `masking`, `CTRL_AI_MASKING_SECRET` | No secret → masking off, rows say `masking: no_secret` |
| Semantic outage | `semantic_outage` | Circuit per provider; `scripts/break-glass.py outage …` |
| Break-glass | `break_glass`, `CTRL_AI_BREAKGLASS_SECRET` | `scripts/break-glass.py issue|revoke|list`; `never_relax` cannot be relaxed, not even through a relaxed pack |

## Audit rows (v2)

`logs/audit.jsonl`, one JSON object per line, never prompt text, response text, keys, tokens or header values.
The row builders in `src/ctrl_ai/core/rows.py` define the fields. Among them:
`identity_error` (unknown team), `masking` (`no_secret`, `error: …`), `mask_store` (`redis` / `memory`),
`restore: unsupported_stream`, `loop.kind`, `budget.price_known`, `by` on a `break_glass` `revoke` row.
Rule ids that are not pack rules: `model-not-approved`, `model-banned`, `model-deprecated`,
`model-team-not-allowed`, `model-data-class`, `budget-exceeded`, `masking-failed`, `semantic-outage`,
`hidden-characters`. A request that fell back to another model has two usage rows under one id (a failure with
0 tokens, then a success with `fallback_used: true`).

## Experiments on LiteLLM v1.103.2

- **Custom auth with subscription pass-through:** `general_settings.custom_auth` receives the key from
  `x-litellm-api-key` when present (it wins over `Authorization`), so the Claude subscription token is never
  treated as the key and is still forwarded upstream (verified with the master key and with a team key). The master
  key works as `Authorization: Bearer`, `x-api-key` and `x-litellm-api-key`. `/health/liveliness` needs no key.
- **Route detection:** inside the pre-call hook the Authorization value in `proxy_server_request.headers` is already
  masked and `secret_fields.raw_headers` is empty, so the route is decided in custom auth (prefix check only) and
  passed in `user_api_key_dict.metadata["ctrl_ai_route"]`. Custom headers such as `x-ctrl-ai-break-glass` and
  `x-claude-code-session-id` are visible unmasked.
- **Rerouting:** setting `data["model"]` in the pre-call hook sends the request to the new model's deployment on
  `/v1/messages`, `/v1/chat/completions` and `/v1/responses`; the usage row's `model_group` is the new model.
- **During-call semantic hook:** `async_moderation_hook` runs on all three endpoints in parallel with the upstream
  call; a 1 s model and a 1 s Jev give about 1 s in total. A block there happens after the upstream answered.
- **Fallback recording:** no fallback field in the standard logging object; LiteLLM logs the failed attempt and then
  the success (with the fallback's `model_group`) under the same call id. LiteLLM also falls back on a 400.
- **Headers on refusal:** a guardrail's `HTTPException(headers=…)` loses its headers; `ProxyException(headers=…)`
  keeps them (used for `Retry-After` on 429).

## Known limits

- Restore of masked values in streams works for chat completions only; `/v1/messages` and `/v1/responses` streams on
  the external route are masked but not restored (`restore: unsupported_stream`). Claude Code uses the subscription
  route, which is never rewritten.
- Redis is optional: loop caps, budgets and the encrypted mask map fail open without it (`unavailable` in the row).
- Circuit-breaker state is per gateway process (not shared through Redis yet).
- Fallback chains need a gateway restart; LiteLLM falls back on client errors (400) as well.
- The prefilters for the case-insensitive secret and injection patterns miss mixed-case spellings such as `PaSsWoRd`.
- A semantic block happens after the model was called (its cost is not recorded in the usage row).
