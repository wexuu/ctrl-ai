# Threat model

## What is protected, and for whom

The gateway protects an organisation that lets AI agents (coding agents such as Claude Code and Codex, and applications built on model SDKs) work with its code, documents and tools. The assets are the organisation's secrets and credentials, the personal data of its customers and staff, its choice of which model providers may see which data, its AI budget, and the integrity of what its agents do. The audit log, which must let an auditor reconstruct decisions without exposing content, is an asset too.

## Threats

| Threat | Example |
|---|---|
| Direct prompt injection | A user, or text pasted into a prompt, tries to make the agent ignore its instructions or help with harm |
| Indirect prompt injection | A web page, document, issue or command output read by a tool carries instructions aimed at the agent |
| Secret leakage to providers | An access key, private key, token or password in a prompt or tool output is sent to a model provider |
| Personal-data leakage to providers | Customer identifiers (IBAN, card numbers, national IDs, e-mail addresses, phone numbers) reach a provider |
| Unapproved models and data classes | A team uses a banned or unreviewed model, or sends confidential data to a model approved only for internal data |
| Runaway agents and cost | An agent loops on the same tool call, a session runs for hours, a team exceeds its budget |
| Misuse of MCP tools | An agent calls a tool its team may not use, a tool that is not approved, or a tool whose description changed after review (a "rug pull") |
| Known exploit patterns | Tool output asks the agent to `curl ... | sh`, load an untrusted pickle, or enable `trust_remote_code` |
| Semantic-check outage | The classifier and the judge are down; requests must not silently go unchecked, nor must all work stop |

## Trust boundaries

- **Clients are untrusted.** Request bodies and headers come from the agent, which may be steered by injected content. The gateway trusts only its own keys (checked by custom auth against hashes in `state/keys.json`) and signed break-glass tokens. Some client headers still steer behaviour (the Claude Code `User-Agent`, the session header); [LIMITATIONS.md](LIMITATIONS.md) says what that allows.
- **Tool results are untrusted.** They are checked like prompts, with their own semantic questions (indirect injection) and the signature feed.
- **Model providers are semi-trusted.** They receive the requests the gateway lets through; masking keeps personal data from external providers, and governance keeps each data class to the models approved for it.
- **The configuration is trusted.** The policy, catalogue, teams, MCP and signature files, and whoever can change them: the admin panel (no sign-in; see [ADMIN.md](ADMIN.md)) and the repository. A wrong policy is a wrong gateway.
- **The audit log must stay content-free.** Rows hold identifiers, labels, counts, scores and timings only, never text, keys or header values; the end-to-end suite checks this on every run.
- **Request text stays in the request.** The gateway keeps the checked text in memory only until the decision row is written; after that the context it keeps for the restore hook and the logger holds no text, only the surrogate map (real values by surrogate), until the response is done or the entry expires.

## Controls

| Control | Covers | Where |
|---|---|---|
| Gateway keys and identity | Unknown, revoked or expired keys; per-team attribution | custom auth, `governance/identity.py` |
| Normalisation | Hidden and tag characters that hide text from the checks | `detect/normalise.py` |
| Policy rules and the secrets pack | Secrets and custom forbidden content in prompts and tool results | `detect/rules.py`, `detect/packs.py` |
| Signature feed | Known exploit patterns, mostly in tool output | `config/signatures.yaml` |
| `pii` and `pl` packs, masking | Personal data: flagged, and replaced by surrogates on the external route, restored in the answer | `detect/detectors.py`, `detect/masking.py` |
| Semantic check | Direct and indirect prompt injection and requests for harm, by a classifier and a judge, per team profile | `semantic/` |
| Shadow check | Classifier misses and drift, measured on a sample of accepted traffic | `semantic/shadow.py`, the Jev trust page |
| Model governance | Unapproved, banned or deprecated models; models below the request's data class; teams outside a model's list | `governance/governance.py` |
| Loop caps and the agent timeout | Runaway sessions and tool loops | `governance/loops.py` |
| Budgets | Spend per team, with downgrade, refusal or alert | `governance/budgets.py` |
| MCP checks | Unapproved servers and tools, changed tool descriptions, injected tool arguments and results | `mcp/core.py` |
| Semantic-outage mode | Classifier and judge down: degrade (flag) or fail closed, per policy and profile | `semantic/outage.py` |
| Break-glass | Time-boxed, signed, audited relaxation for urgent work; `never_relax` rules stay on | `governance/breakglass.py` |
| Audit log | Reconstruction of every decision without content | `core/rows.py` |

## Out of scope and not covered

These are stated in full in [LIMITATIONS.md](LIMITATIONS.md):

- model answers (only requests are checked, apart from MCP tool results), and tool calls the model proposes, which are seen only in the next request;
- earlier turns, resent or rewritten history, system prompts and the request's `tools` array;
- data flow across requests (no taint tracking), and session behaviour beyond the loop caps and budgets;
- encodings other than Unicode normalisation (base64, hex, URL encoding, confusable characters), and mixed-case spellings that the case prefilters miss;
- clients that claim to be Claude Code through their headers;
- the security of the model providers, of the agents' own machines and of tools that run outside the gateway;
- the admin panel's access control (open access; single sign-on is a design in [ADMIN.md](ADMIN.md), not built);
- tamper evidence for the audit log;
- availability: ctrl-ai's own errors fail open, and shared state fails open without Redis.
