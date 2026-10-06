# Decision models

The semantic check asks a model how likely a text is an attack on the agent (prompt injection, an attempt to override or reveal the agent's instructions, exfiltration, help with harm). The gateway uses such a model in three roles. Each role is configured separately, and any role can be switched off.

| Role | When it is asked | Variable | Default |
|---|---|---|---|
| Classifier | Every request with text to check, once per source (prompt, tool result), in parallel | `CTRL_AI_CLASSIFIER_MODEL` | `jev` |
| Judge | When the classifier rejects, is unsure or is unavailable (`judge.when`, `jev.accept_below` in the policy) | `CTRL_AI_JUDGE_MODEL` | `groq/openai/gpt-oss-safeguard-20b` |
| Shadow | In the background, for a random share (`judge.shadow.rate`) of the requests the classifier accepted | `CTRL_AI_SHADOW_MODEL` | the judge's model |

The policy still decides whether a role runs at all: `jev.enabled` switches the classifier, `judge.enabled` the judge and the shadow check. `CTRL_AI_SHADOW=0` turns the shadow check off without editing the policy.

All three roles share one interface (`src/ctrl_ai/semantic/models.py`): `score(text, source)` returns a `Score` with a 0..1 score, the model name, latency, cost and an error when there is no answer; `sample(text, source, n)` asks repeatedly and returns the share of positive answers, which the shadow check records. A model never raises: a timeout or a failure becomes `unavailable` or `error`, and the profile's `on_semantic_unavailable` decides what happens then.

## Model specs

A role's variable holds a spec:

- `jev`: the Jev decision API ([JEV.md](JEV.md)), configured by the `JEV_*` variables.
- `none` (or empty): no model in that role.
- anything else: a LiteLLM model string, called in-process with the judge prompt (`src/ctrl_ai/semantic/judge.py`), which asks for a JSON verdict (`{"verdict": 0 or 1, "category", "reason"}`). Examples: `groq/openai/gpt-oss-safeguard-20b`, `anthropic/claude-haiku-4-5`, `openai/llama3.1` with an API base.

Settings per role:

| Variable | Meaning |
|---|---|
| `CTRL_AI_CLASSIFIER_MODEL` | classifier spec |
| `CTRL_AI_CLASSIFIER_API_BASE` | endpoint for a LiteLLM classifier; empty for the provider's default |
| `CTRL_AI_CLASSIFIER_TIMEOUT_S` | timeout for a LiteLLM classifier (default 8); Jev uses `JEV_TIMEOUT_S` |
| `CTRL_AI_JUDGE_MODEL` | judge spec |
| `CTRL_AI_JUDGE_API_BASE` | endpoint for the judge; empty for the provider's default |
| `CTRL_AI_JUDGE_TIMEOUT_S` | judge timeout in seconds (default 8) |
| `CTRL_AI_SHADOW_MODEL` | shadow spec; uses the judge's API base and timeout |
| `GROQ_API_KEY`, `ANTHROPIC_API_KEY` | provider keys, chosen by the spec's prefix (`groq/`, `anthropic/`) |

The gateway reads all of these once at start-up; change them and restart the gateway.

## Back ends

**Jev.** A hosted classifier that answers per-question probabilities, about 100 ms per call. Its per-question answers are kept in the audit row. Without `JEV_API_KEY` it reports `disabled` and the judge decides alone.

**Groq.** The default judge, `gpt-oss-safeguard-20b`, a policy-following safety model on Groq's free tier. It answers yes or no, so a live score is 0 or 1; the shadow check samples it at temperature 1 to get a probability.

**Anthropic.** Any Claude model works as a judge (`anthropic/claude-haiku-4-5`), with `ANTHROPIC_API_KEY`. The test stack uses this spec against its stub Anthropic server.

**A local model.** Any OpenAI-compatible server works through LiteLLM's `openai/` prefix: Ollama, vLLM, LM Studio. Set the spec to `openai/<model name>` and the API base to the server's `/v1` endpoint. Those servers ignore the API key but reject a request whose key is empty, so when a role has an API base and no key, the gateway sends a placeholder key (`no-key`). Small general models follow the JSON verdict format less reliably than a safety model; an answer that cannot be parsed is recorded as `error` and treated as no answer.

## Running without paid keys

- **Classifier off.** `CTRL_AI_CLASSIFIER_MODEL=none`. Every request goes to the judge as "classifier unavailable"; the audit row's `jev` field says `unavailable` / `not_configured`, and the classifier's circuit breaker is not involved.
- **Judge on a local server.** For example with Ollama:

  ```
  CTRL_AI_JUDGE_MODEL=openai/llama3.1
  CTRL_AI_JUDGE_API_BASE=http://ollama:11434/v1
  CTRL_AI_JUDGE_TIMEOUT_S=20
  ```

  The API base must be reachable from the gateway container: a service on the same compose network, or the host's address on that network. A local model is slower than a hosted one; raise the timeout to match, because the judge runs alongside the model call.
- **Judge on Groq's free tier.** The default; needs only `GROQ_API_KEY`.
- **The stub stack.** `make test` runs the gateway against stub Jev and Anthropic servers with fake keys (`tests/e2e/test.env`); nothing leaves the machine.

With both the classifier and the judge off, the semantic check has no answer and each profile's `on_semantic_unavailable` applies (a strict profile then refuses requests). The deterministic checks (rules, packs, signatures, masking, governance) run either way.

## Audit rows

The decision row keeps its field names: `jev` holds the classifier's answer (`status`, `attack`, `answers`, `model`, `input_tokens`, `cost_usd`, `latency_ms`, `truncated`, `error`) whichever back end produced it, and `judge` holds the judge's (`status`, `score`, `model`, `latency_ms`, `cost_usd`, `error`, `category`). The judge's free-text reason is never logged, because it may paraphrase the prompt. The circuit breakers and incident rows keep the component names `jev` and `judge` for the classifier and judge roles.
