# 0001. Gateway host: LiteLLM proxy, an own proxy, or both

- **Status:** Proposed
- **Date:** 2026-10-09
- **Evidence gathered:** a streaming-hold spike on LiteLLM v1.103.2 (local branch `spike/streaming-hold`) and a read-up of the alternatives; web sources were checked on 2026-10-09.

## Context

ctrl-ai runs as a set of extensions inside the LiteLLM proxy (`ghcr.io/berriai/litellm:v1.103.2`): custom auth, three guardrails (pre-call, during-call, post-call), an MCP guardrail and a logging callback, about 460 lines in `src/ctrl_ai/adapters/litellm/`. Everything else (detectors, policy, decision models, audit, admin app) is LiteLLM-free. LiteLLM supplies the client wire formats, provider translation, routing and fallbacks, the MCP gateway, subscription pass-through of client headers, and OpenTelemetry spans.

So far the gateway checks only what goes **to** the model. The next controls act on what comes **back**:

- **Holding tool calls.** Each streamed tool call is held until it is complete, decided on, then released, rewritten or replaced with a refusal. Text is not held.
- **Response-side checks** for secrets, PII and dangerous output.
- **Tool-definition pinning** from the request `tools` array.
- **Out-of-band approvals** that keep a tool call waiting until a person answers.
- **A provenance graph** built from audit rows.

All of these must work on the three wire formats the target agents use: Anthropic Messages (Claude Code), OpenAI Responses (Codex) and OpenAI Chat Completions (most SDK applications), streaming and not. The question is whether LiteLLM's extension points carry this, or whether the gateway should own the proxy layer.

## Spike: holding tool calls inside LiteLLM

### What was built

`src/ctrl_ai/adapters/litellm/hold.py` is a `CustomGuardrail` registered with `mode: [pre_call, post_call]` in a copy of the gateway configuration (`deploy/litellm/config.spike.yaml`). It does the following:

- **Streams** (`async_post_call_streaming_iterator_hook`): text chunks pass through as they arrive. From the first chunk of a tool call until the call is complete, the chunks are held. Then a stub decision runs: it refuses any call whose name or arguments contain `HOLD-BLOCK-TEST`.
  - **Allowed:** the held chunks are released unchanged.
  - **Refused:** they are replaced by a well-formed text block saying the call was blocked, and the stop reason is changed so the client does not wait for a tool result.
- **Non-streaming responses** (`async_post_call_success_hook`): the same decision, with the refused call rewritten in the JSON body.
- **Audit:** every decision writes a content-free `hold` audit row with the tool name, the decision and the time held.

The stub Anthropic server answers a prompt containing `TOOL-CALL-TEST` with a text block followed by a `tool_use` block, both streamed and not. The streamed tool input arrives in three pieces 50 ms apart. `scripts/spike_hold.py` sends every case through the gateway and records the raw responses and the timings. The baseline is the standard configuration with the same stub.

### What LiteLLM hands the hook

The hook point is the same for all three endpoints, but the objects it receives are not:

| Endpoint | Streaming | Non-streaming | Tool call appears as |
|---|---|---|---|
| `/v1/messages` | raw upstream SSE bytes; one chunk can hold several events | Anthropic message `dict` | `content_block_start` (`tool_use`) … `input_json_delta` … `content_block_stop` |
| `/v1/chat/completions` | `ModelResponseStream` objects | `ModelResponse` | `delta.tool_calls[i]` chunks until `finish_reason` |
| `/v1/responses` | typed events (`OutputItemAddedEvent`, `FunctionCallArgumentsDeltaEvent`, …) | `ResponsesAPIResponse` | `output_item.added` (`function_call`) … `output_item.done` |

The pre-call hook sees the request `tools` array on all three endpoints (`call_type` is `anthropic_messages`, `acompletion` and `aresponses` respectively). Pinning tool definitions can therefore live in pre-call without a separate parser.

### Results

Median of 10 runs per row, in milliseconds, given as **baseline / hold**. Stub upstream, local Docker, one gateway replica.

- **First byte:** time to the first byte of the response.
- **Tool call visible:** time until the client first sees the tool call, or its replacement.

| Endpoint | Mode | Case | First byte | Tool call visible | Total | Hold works | What the client receives |
|---|---|---|---|---|---|---|---|
| `/v1/messages` | stream | allow | 74 / 73 | 91 / 290 | 293 / 291 | yes | original `tool_use` block, released whole after `content_block_stop` |
| `/v1/messages` | stream | refuse | 73 / 71 | 88 / 287 | 291 / 288 | yes | text block at the tool block's index; `stop_reason` `tool_use` → `end_turn` |
| `/v1/messages` | stream | text only | 72 / 67 | – | 86 / 85 | n/a | unchanged |
| `/v1/messages` | JSON | allow | 66 / 68 | – | 66 / 68 | yes | unchanged |
| `/v1/messages` | JSON | refuse | 64 / 64 | – | 64 / 64 | yes | `tool_use` block replaced by a text block; `stop_reason` `end_turn` |
| `/v1/messages` | JSON | text only | 67 / 66 | – | 67 / 66 | n/a | unchanged |
| `/v1/chat/completions` | stream | allow | 71 / 67 | 86 / 289 | 291 / 293 | yes | original `tool_calls` chunks, released after the last argument chunk |
| `/v1/chat/completions` | stream | refuse | 70 / 67 | 83 / 285 | 288 / 288 | yes | `content` chunk with the refusal, `finish_reason` `stop`, then `[DONE]` |
| `/v1/chat/completions` | stream | text only | 68 / 73 | – | 85 / 90 | n/a | unchanged |
| `/v1/chat/completions` | JSON | allow | 68 / 64 | – | 68 / 64 | yes | unchanged |
| `/v1/chat/completions` | JSON | refuse | 66 / 64 | – | 66 / 64 | yes | `tool_calls` removed, refusal appended to `content`, `finish_reason` `stop` |
| `/v1/chat/completions` | JSON | text only | 64 / 64 | – | 64 / 64 | n/a | unchanged |
| `/v1/responses` | stream | allow | 34 / 67 | 86 / 291 | 307 / 301 | yes | original `function_call` item events, released after `output_item.done` |
| `/v1/responses` | stream | refuse | 32 / 31 | 84 / 295 | 303 / 307 | yes | a `message` item (added, part added, text delta, text done, part done, item done); `response.completed` output rewritten to match |
| `/v1/responses` | stream | text only | 68 / 69 | – | 96 / 100 | n/a | unchanged |
| `/v1/responses` | JSON | allow | 68 / 68 | – | 68 / 68 | yes | unchanged |
| `/v1/responses` | JSON | refuse | 69 / 68 | – | 69 / 69 | yes | `function_call` output item replaced by a `message` item |
| `/v1/responses` | JSON | text only | 68 / 68 | – | 68 / 68 | n/a | unchanged |

All 360 requests returned 200 and well-formed streams.

The median time held, from the hold audit rows, was about 200 ms on every streaming endpoint (messages 201, chat 202, responses 207). That equals the time the stub takes to stream the tool input, and non-streaming responses held for 0 ms.

What the numbers say:

- **Text is not delayed.** First byte, text-only totals and overall totals are within run-to-run noise of the baseline. The spread of first byte on `/v1/responses` streams (31–69 ms) appears in the baseline too.
- **A tool call reaches the client only once it is complete.** The delay equals the time the model spends generating its arguments. An agent cannot run a tool call before the call is complete anyway, so it starts the tool at the same moment as without the hold, plus the decision time (here about 0).
- **The check itself costs nothing measurable.** Without a model in the decision, the hook adds no measurable time to the stream.

### What LiteLLM makes awkward

1. **Three object models in one hook.**
   - `/v1/messages` hands over raw bytes, so the hook re-parses SSE and must cope with several events per chunk.
   - Chat hands over pydantic chunk objects.
   - Responses hands over typed pydantic events.

   The hold logic is one idea, but it is written three times against LiteLLM's internal types.
2. **Responses replacements must be valid pydantic events.** A replacement event built from a plain dict failed validation. LiteLLM then ended the stream with a well-formed `response.failed`, which is safe, but the hook has to build `ContentPartDonePartOutputText` and similar classes exactly.
3. **LiteLLM's own Responses stream is loose:**
   - it sends `data:` lines without `event:` lines;
   - `sequence_number` is mostly missing;
   - the `function_call` item's `output_item.done` arrives before the text item's done events.

   A strict client may care. The spike's refusal follows the same order.
4. **Coupling to a fast-moving internal surface.**
   - The object types above are internal: the documented contract is only "the hook receives the stream and yields items" ([LiteLLM custom guardrail docs](https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail)).
   - LiteLLM published ten releases between 28 September and 8 October 2026, v1.103.0 to v1.104.2 ([GitHub releases](https://github.com/BerriAI/litellm/releases)).
   - Every image upgrade therefore needs the spike's cases as regression tests.
5. **Covered only for the Anthropic upstream used in the spike.**
   - `/v1/messages` delivers raw provider bytes when the upstream is Anthropic. With an OpenAI-format upstream behind `/v1/messages`, the chunks may arrive in another shape; this was not tested.
   - Codex's freeform tools (`custom_tool_call` items, `input` instead of `arguments`) were not covered either.
6. **Supply chain.** LiteLLM's PyPI package was backdoored for a few hours on 24 March 2026 (versions 1.82.7 and 1.82.8) ([Comet write-up](https://www.comet.com/site/blog/litellm-supply-chain-attack/), [PyPI Stats write-up](https://pypistats.com/blog/litellm-pypi-supply-chain-compromise-how-a-popular-llm-proxy-became-a-credential-stealing-backdoor-march-24-2026)). A security gateway that hosts on it should pin the image by digest and review each upgrade.

### Holding a call for out-of-band approval

The hook can await anything, including an approval, while it holds the chunks. Whether the client keeps the connection open is a separate question. From the v1.103.2 source (not measured in the spike):

- **`/v1/messages`:** the stream is wrapped in `wrap_sse_stream_with_keepalive_pings` (`proxy/common_utils/sse_keepalive.py`). That wrapper sits outside the guardrail hook and writes Anthropic `ping` events into every idle gap of `anthropic_sse_ping_interval_seconds`, 15 s by default. A held call therefore keeps the connection alive.
- **Chat Completions and Responses:** `_iter_with_keepalive` in `proxy/proxy_server.py` writes `: ping` SSE comments into idle gaps, also outside the hook. It is controlled by `litellm_settings.sse_keepalive_ping_interval_seconds`, which is off by default, so it has to be enabled.

Client-side overall timeouts differ per harness and were not measured. Approvals that take seconds to a minute fit inside the stream. Longer ones should refuse with a "waiting for approval" message and let the agent retry once approved.

### Running the spike

```
git switch spike/streaming-hold
make spike                 # baseline, then hold; each on a fresh test stack
make spike-baseline        # standard configuration only
make spike-hold            # deploy/litellm/config.spike.yaml only
```

- **Ports and project:** the targets start the keyless test stack as project `ctrl-ai-spike` on ports 4210, 4310, 9211 and 9212, so a gateway already running on 4000/4100 is not touched.
- **Output:** they write the raw responses and `*-summary.json` files to `tests/e2e/runtime/spike/` (gitignored). `SPIKE_REPEAT` sets the runs per case (default 10).
- **Audit rows:** the hold decisions appear as `"type":"hold"` rows in `tests/e2e/runtime/audit.jsonl`.
- **Fresh stack per run:** each run uses a fresh stack because the loop caps throttle the master key after a few hundred requests.

## Options

The criteria for every option:

- licence;
- self-hosting;
- the client APIs exposed (Anthropic Messages, OpenAI Responses, Chat Completions, MCP);
- whether custom code can inspect and rewrite a response mid-stream, which the tool-call hold needs;
- maturity.

GitHub figures were read through the GitHub API on 2026-10-09.

### A. LiteLLM proxy as host (current)

| | |
|---|---|
| Licence | MIT, except an `enterprise/` directory under its own licence ([LICENSE](https://github.com/BerriAI/litellm/blob/main/LICENSE)) |
| Self-hosted | yes (pinned Docker image) |
| Client APIs | `/v1/messages`, `/v1/responses`, `/v1/chat/completions`, MCP gateway; all used today |
| Mid-stream rewrite | yes: shown by the spike for all three endpoints, streaming and not |
| Maturity | about 60.5k stars; very active (v1.104.2 on 2026-10-08) |

- **For:** it already runs. The spike shows that the hold, the refusal rewrite and pre-call access to `tools` work through public extension points with no measurable overhead. The provider translation, routing, fallbacks, MCP gateway and subscription pass-through come for free.
- **Against:** the awkward points listed above. Hook payloads are internal types that change between releases, and the upstream release cadence and supply chain need active management.

### B. An own thin proxy

A small ASGI service (for example Starlette with httpx) that terminates the three wire formats and forwards to providers.

- **Licence and hosting:** ours, self-hosted.
- **Client APIs:** only what is written.
- **Mid-stream rewrite:** full control. The SSE parsers and the hold are the same work as in the spike, but written against the wire formats themselves rather than LiteLLM's object model.

Rough effort in AI-assisted working days:

| Work | Days |
|---|---|
| Pass-through for the three endpoints (same-format upstream only, streaming, header pass-through for subscriptions) | 3–4 |
| Keys, budgets and per-team model routing, moved from LiteLLM into the gateway | 2–3 |
| MCP proxying | 2–3 |
| Cross-format translation (for example Codex to an Anthropic model) | several more, ongoing as the formats change |

- **For:** one object model and no dependency on a fast-moving host. It is smaller to audit, which suits a security product.
- **Against:**
  - A week or more before parity, and provider quirks become ctrl-ai's problem.
  - It loses LiteLLM's breadth: about 100 providers, fallbacks, cost maps and OpenTelemetry spans.

### C. Hybrid: own front proxy, LiteLLM behind it

The own proxy from option B terminates the client connection, parses the three formats, holds and rewrites tool calls, and runs the checks. It forwards to LiteLLM, which keeps provider translation, routing, fallbacks and the MCP gateway.

- **Licence and hosting:** ours plus MIT; self-hosted.
- **Client APIs:** the three formats, as LiteLLM exposes them.
- **Mid-stream rewrite:** full control in the front proxy.
- **For:**
  - The response side is written once against stable public wire formats, not LiteLLM internals.
  - LiteLLM can be upgraded or replaced behind it.
  - The spike's per-format logic moves over almost unchanged, since it already re-parses `/v1/messages` bytes.
- **Against:**
  - Two hops and two configurations.
  - Auth and identity must be resolved in the front proxy and passed on.
  - About 3–5 days to stand up before it adds anything over option A.

### D. Other gateways

| Gateway | Licence | Self-hosted | Client APIs | Custom mid-stream rewrite | Maturity (2026-10-09) |
|---|---|---|---|---|---|
| **Agent Router**, formerly Envoy AI Gateway | Apache-2.0 | yes, Kubernetes (Envoy Gateway CRDs) | `/v1/chat/completions`, `/anthropic/v1/messages`, `/v1/responses`, MCP | Only through an extra Envoy external processor (gRPC). `FULL_DUPLEX_STREAMED` mode lets it hold and re-chunk response bodies, so the hold is our own service either way. | about 2.2k stars; v1.2.0 on 2026-10-07; renamed and moved to the Agentic AI Foundation |
| **Kong Gateway** (open source) + AI plugins | Apache-2.0 | yes | Open-source line ends at 3.9.3 (2026-06-17), whose `ai-proxy` accepts OpenAI, Bedrock and Gemini formats. Native Anthropic format and `llm/v1/responses` are documented from 3.10/3.11, which are not in the open-source repository. | Lua plugins in `body_filter` can rewrite chunks; Go, Python and JS plugin servers are more limited | 44k stars; enterprise features carry the AI roadmap |
| **Portkey Gateway** | MIT | yes | chat completions, `/v1/messages`, `/v1/responses` handlers present | Output hooks on streaming requests are "informational only"; their results arrive after `[DONE]` | about 13k stars; last push 2026-05-25, last release v1.15.2 (2026-01-12) |
| **Bifrost** (Maxim) | Apache-2.0 (enterprise build separate) | yes | `/openai/v1/chat/completions`, `/openai/v1/responses`, `/anthropic/v1/messages`, MCP | Go plugins (`.so`) with `HTTPTransportStreamChunkHook`, which can modify or drop each chunk. Its guardrails (enterprise) can buffer a stream and replay it. | about 8.7k stars; very active |
| **Helicone AI Gateway** | GPL-3.0 (Rust gateway; was Apache-2.0) | yes | OpenAI-compatible | no custom streaming hook | Helicone joined Mintlify on 2026-03-03; the product is in maintenance mode; Rust gateway last commit 2025-11-21 |
| **Cloudflare AI Gateway** | proprietary service | no | provider pass-through, OpenAI-compatible | Guardrails "do not support streaming"; no custom code in the path | managed service |
| **agentgateway** | Apache-2.0 | yes, standalone or Kubernetes | OpenAI-compatible, Anthropic messages, Responses, MCP, A2A | Built-in guards (regex, moderation APIs, webhook) can evaluate streamed text windows and block; holding tool calls needs changes in its Rust code | about 5.3k stars; v1.6.0 on 2026-10-02 |
| **Apache APISIX** AI plugins | Apache-2.0 | yes | OpenAI-compatible proxying | Lua plugins | about 17k stars; v3.19.0 on 2026-09-28 |
| **TensorZero** | Apache-2.0 | yes | own inference API, OpenAI-compatible | none for third-party code | repository archived (last release 2026.6.0, 2026-06-04) |

What the table means for ctrl-ai:

- **None removes the core work.** Where custom code can rewrite a stream (Agent Router via external processor, Kong via Lua, Bifrost via Go plugins), the parsing and holding of the three formats is still ours. It would also be in a second language, or behind a gRPC hop, away from the Python engine.
- **The others fail on basics.** Portkey and Cloudflare cannot block a streamed output. Helicone and TensorZero are no longer developed. Kong's open-source line lacks the Anthropic format Claude Code needs.
- **Bifrost and Agent Router are the credible alternatives.** Either would be a rewrite of the adapter layer in Go or a sidecar design. The gain is speed and a cleaner proxy core; the loss is a second language next to the Python engine.

## Consequences

### If LiteLLM stays the host (option A)

- **Holding tool calls and response-side checks** ship as one post-call streaming guardrail. Three per-format handlers sit behind one internal interface (the tool calls found, a decision per call, and a release, rewrite or refusal). The spike is its first draft. Text checks for secrets and PII use the same hook on text chunks, buffered per sentence or block rather than per token.
- **Tool-definition pinning** reads `tools` in pre-call on all three endpoints. No extra parsing is needed.
- **Approvals** can await inside the hold. `sse_keepalive_ping_interval_seconds` must be enabled for Chat Completions and Responses, and approvals longer than a client's timeout need the refuse-then-retry pattern.
- **Provenance** is unaffected: it is built from audit rows, which the hold already writes per decision.
- **Upgrades:** every LiteLLM image upgrade runs the spike's cases as e2e tests before it is accepted, and the image is pinned by digest.

### If the gateway moves to the hybrid later (option C)

- The per-format handlers move from LiteLLM types to wire-level parsing; `/v1/messages` already works on bytes.
- The engine and the decision interface stay unchanged.
- Auth moves to the front proxy.
- Nothing in the audit format or the admin app changes.

### If the gateway moves to an own proxy (option B)

- As option C, plus provider routing, fallbacks, budgets, MCP proxying and OpenTelemetry move into ctrl-ai.

## Recommendation

**Keep LiteLLM as the host now, and design the response side so that the hybrid stays a cheap exit.** The spike shows the hard requirement works on LiteLLM v1.103.2:

- hold a streamed tool call, decide, then release or replace it with a well-formed refusal;
- on all three wire formats, streaming and not;
- with no measurable overhead beyond the hold itself.

Moving now would spend a week or more to reach the position the gateway already has.

**Isolate the dependency.** Put the hold and the response checks behind a format-neutral interface in ctrl-ai's own code, with the LiteLLM guardrail as a thin shim. Turn the spike's cases into e2e tests that every LiteLLM upgrade must pass, and pin the image by digest. If LiteLLM's hook payloads change too often, or a needed control cannot be expressed in its hooks, move to option C: an own front proxy for the wire formats and the hold, with LiteLLM behind it for providers. That move then touches only the shim.

**None of the other gateways is a better host for this project today.** Bifrost and Agent Router are the credible alternatives, but both mean writing the same per-format hold in Go or as an external gRPC processor, away from the Python engine. The rest cannot rewrite a streamed response, or are no longer actively developed.

## Sources

Checked on 2026-10-09.

- **LiteLLM**
  - Custom guardrails and hooks: https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail
  - Releases: https://github.com/BerriAI/litellm/releases
  - Licence: https://github.com/BerriAI/litellm/blob/main/LICENSE
  - Source read from the `ghcr.io/berriai/litellm:v1.103.2` image: `litellm/proxy/utils.py`, `litellm/proxy/proxy_server.py`, `litellm/proxy/common_request_processing.py`, `litellm/proxy/common_utils/sse_keepalive.py`, `litellm/types/llms/openai.py`
  - PyPI compromise of 24 March 2026: https://www.comet.com/site/blog/litellm-supply-chain-attack/ and https://pypistats.com/blog/litellm-pypi-supply-chain-compromise-how-a-popular-llm-proxy-became-a-credential-stealing-backdoor-march-24-2026
- **Agent Router (formerly Envoy AI Gateway)**
  - Repository and rename: https://github.com/theagentrouter/agent-router
  - Supported endpoints: https://github.com/theagentrouter/agent-router/blob/main/site/docs/capabilities/llm-integrations/supported-endpoints.md
  - Envoy external processor body modes: https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_proc/v3/processing_mode.proto
- **Kong**
  - Repository and tags: https://github.com/Kong/kong
  - AI Proxy plugin: https://developer.konghq.com/plugins/ai-proxy/
- **Portkey**
  - Gateway: https://github.com/Portkey-AI/gateway
  - Guardrails on streaming: https://portkey.ai/docs/product/guardrails
- **Bifrost**
  - Repository: https://github.com/maximhq/bifrost
  - Plugins: https://docs.getbifrost.ai/plugins/writing-plugin
  - Integrations: https://docs.getbifrost.ai/integrations/what-is-an-integration
  - Guardrails: https://docs.getbifrost.ai/enterprise/guardrails
- **Helicone**
  - AI gateway: https://github.com/Helicone/ai-gateway
  - Joining Mintlify: https://helicone.ai/blog/joining-mintlify
- **Cloudflare AI Gateway guardrails:** https://developers.cloudflare.com/ai-gateway/features/guardrails/supported-model-types/
- **agentgateway**
  - Repository: https://github.com/agentgateway/agentgateway
  - Streaming guards: `crates/agentgateway/src/llm/policy/mod.rs`
- **Apache APISIX:** https://github.com/apache/apisix
- **TensorZero:** https://github.com/tensorzero/tensorzero
