# Known limitations

What the gateway does not do, or does only in part. [THREAT_MODEL.md](THREAT_MODEL.md) puts these in context.

## What is checked

- **Requests only.** The gateway checks what goes to the model, not what comes back. Model answers are not inspected; the post-call hook only restores masked values. The one exception is MCP: tool results returned through the gateway's MCP checks pass the deterministic checks.
- **Proposed tool calls are seen one request late.** A tool call the model proposes reaches the gateway as part of the next request (as a `tool_call` piece), after the client has already run it. Only MCP tools behind the gateway are checked before they run.
- **Only the newest turn.** Each request is checked on its newest turn: the latest user message and the tool results and tool calls that belong to it. Earlier messages are not re-checked, so history that a client resends or rewrites passes unchecked. System prompts are never checked.
- **No cross-request state beyond loop caps and budgets.** Each request is judged on its own; nothing tracks where data came from across turns (no taint tracking) or the history of a session, apart from the loop counters and budget reservations in Redis.
- **The request's `tools` array is not inspected.** Tool definitions that a client sends with a request are not checked. Tool description pinning covers only MCP servers behind the gateway; their tools are re-listed every ten minutes, and when a server cannot be listed its tools are allowed (fail open) and the row records `pin_check` with the reason.
- **Text limits.** The deterministic checks read the first 200,000 characters of each piece; the Jev classifier reads the first 20,000 characters of each source and the judge the first 12,000. Text beyond those limits is not checked by that step (the Jev verdict says `truncated`).

## Detection

- **Encoding coverage is Unicode normalisation only.** The checked copy is NFKC-normalised, Unicode tag characters are decoded and hidden characters are removed. There is no base64, hex or URL decoding and no mapping of confusable characters (a Cyrillic letter in a Latin word stays as it is). The rules and the semantic check are weaker on non-English text.
- **Case prefilters.** The secret-assignment and hidden-instruction patterns are case-insensitive, but a cheap substring prefilter runs first and knows only the lower-case, upper-case and capitalised spellings of its trigger words; a mixed-case spelling such as `PaSsWoRd` or `iGnOrE` is not found.
- **Loop detection is exact.** Repeated prompts and identical tool calls are compared by hash, so a loop whose arguments change slightly on every round counts as distinct calls (the request, token and session-length caps still apply).
- **Claude Code reminders.** `<system-reminder>` blocks at the start of a user message are excluded from the semantic check and from the policy rules and identifier packs (the secrets and signatures packs still check them) when the request's `User-Agent` starts with `claude-cli/` or `x-app` is `cli`. Both are headers the client controls, so any client can claim to be Claude Code.

## Decisions and refusals

- **Refusals are explicit.** A refused request gets a message with the rule id, and a semantic refusal carries the score (and, with a custom `judge.block_message`, the judge's category and reason). This helps users and also tells an attacker which rule fired.
- **The engine fails open.** An unexpected error in ctrl-ai's own code allows the request and records `error: "internal: <Class>"` in the row; so do errors in the MCP content checks. Masking on the external route is the exception: it fails closed by default.
- **A semantic refusal comes after the model call.** The semantic check runs alongside the model call, so a request it refuses has already been sent to the provider and is billed; only the answer is withheld.
- **Approvals are break-glass overrides only.** There is no per-request human approval flow: a blocked request can only be retried under a signed, time-boxed override that relaxes named controls (`scripts/break-glass.py`).
- **Shared state is optional.** Without Redis the loop caps, budgets and the encrypted mask map fail open (`unavailable` in the row). Circuit-breaker state is per gateway process, not shared between replicas.

## Data handling

- **The subscription route is never rewritten.** Requests that carry a Claude subscription token go to Anthropic unchanged; personal data on that route is flagged, and masked only in the copy sent to the semantic check.
- **Streamed answers on `/v1/messages` and `/v1/responses` are not restored.** On the external route those requests are masked, but the surrogates in a streamed answer stay in place (`restore: unsupported_stream` in the row). Chat-completions streams and all non-streamed answers are restored.
- **The surrogate map lives on after the decision.** Once the decision row is written the gateway drops the request's text from its in-process context cache, but keeps the surrogate map (real values by surrogate) there until the entry expires (ten minutes) or is pushed out (10,000 entries), because the restore hook needs it while the response is produced. The map is also kept in Redis, encrypted with the masking secret, for 24 hours.
- **The audit log has no tamper evidence.** `logs/audit.jsonl` is a plain JSON-lines file; nothing chains or signs the rows. In a cluster it goes to stdout, and the log store is responsible for integrity.
- **Model fallbacks need a restart.** The router's fallback chains are read at start-up; LiteLLM also falls back on a client error (400).
