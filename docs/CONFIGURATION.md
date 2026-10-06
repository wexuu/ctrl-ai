# Configuration

The gateway's behaviour lives in five YAML files in `config/`. Each has a JSON Schema in `config/schema/`, and the unit tests check that the shipped files and every profile match their schemas. The gateway re-reads a file when it changes, so most edits apply to the next request without a restart. An invalid file is ignored, and the last valid version stays active. The admin panel edits these files, validates them before saving and keeps every previous version in `state/history/`.

| File | Variable | What it holds |
|---|---|---|
| `policy.yaml` | `CTRL_AI_POLICY_FILE` | Mode, profiles, rule packs, custom rules, semantic check, masking, loop caps, break-glass and outage settings |
| `teams.yaml` | `CTRL_AI_TEAMS_FILE` | Departments and teams: each team's profile, data class, default model, budget and mode |
| `models.yaml` | `CTRL_AI_MODELS_FILE` | The model catalogue: which models are approved, for which teams and data classes, at what price, and their fallbacks |
| `mcp.yaml` | `CTRL_AI_MCP_FILE` | Approved MCP tool servers, the teams allowed to use them, and the pinned hash of each tool description |
| `signatures.yaml` | `CTRL_AI_SIGNATURES_FILE` | The known-exploit signature feed, each entry with its source and a match / near-miss test pair |

Gateway keys (`state/keys.json`) and break-glass overrides (`state/break_glass.json`) are runtime state, not configuration. They are issued from the admin panel and the `scripts/break-glass.py` tool.

## Rule packs

A rule pack is a set of built-in detectors. The policy switches packs on by id in `rule_packs`:

| Pack | Rule ids | What it finds | Default action |
|---|---|---|---|
| `pii` | `pii-email`, `pii-phone`, `pii-card`, `pii-iban` | E-mail addresses; phone numbers (international `+<country code>` numbers, and three groups of three digits); payment card numbers (Luhn-checked); IBANs (mod-97 checked, country lengths) | `mask` |
| `pl` | `pl-pesel`, `pl-nip`, `pl-account` | Polish national identifiers: PESEL (date and check digit), NIP (check digit), the 26-digit NRB account number | `mask` |
| `secrets` | `secret-aws-key`, `secret-private-key`, `secret-github-token`, `secret-generic-api-key`, `secret-jwt`, `secret-password-assignment` | Cloud keys, private keys, tokens and passwords | `block` |
| `signatures` | the ids in `signatures.yaml` (`sig-hidden-instruction`, `sig-curl-pipe-shell`, ...) | Known exploit patterns and hidden instructions | per signature |

The identifier rules (`pii`, `pl`) have the action `mask`. On the external route the gateway rewrites the value with a realistic fake before the request leaves (if `masking` is on and the entity is listed in `masking.entities`), and the answer gets the real value back. Where nothing is rewritten, for example on the Claude subscription route, the finding is a flag. The packs are listed in one registry (`src/ctrl_ai/detect/packs.py`), which the policy schema, the admin panel and the dashboard read.

A finding also sets the request's data class, which model governance compares with each model's `data_class_max`. Card numbers, IBANs, the Polish identifiers and secrets make a request `confidential`. E-mail addresses, phone numbers and any other finding make it `internal`. A value that is masked before it leaves does not count.

A `rules:` entry with the id of a pack rule overrides that rule's `action`, `enabled`, `severity` and `sources`; the detector stays. For example, to block card numbers instead of masking them:

```yaml
rules:
  - id: pii-card
    type: contains
    value: unused
    action: block
```

Other `rules:` entries are custom rules (`contains` or `regex`), tried in file order.

## Profiles

A profile says what the semantic check's verdict does for a team. `teams.yaml` gives each team a profile, and `default_profile` in the policy covers everyone else, including the master key.

| Profile | Mode | A likely attack | Semantic check unavailable |
|---|---|---|---|
| `observe` | monitor | recorded only | allowed |
| `balanced` | enforce | flagged for review | allowed |
| `strict` | enforce | refused | refused |

Deterministic findings follow the mode: in `enforce` a blocking rule refuses the request, in `monitor` it is recorded as `would_block`. A team's own `mode` in `teams.yaml` overrides the profile's. A global `mode: monitor` in the policy switches the whole organisation to observe-only.

## The example organisation

The shipped `config/` describes a neutral example organisation, meant to be replaced by your own:

| Department | Team | Profile | Data class | Budget when exceeded |
|---|---|---|---|---|
| HR | `people-ops` | strict | confidential | block |
| DevOps | `platform-ops` | balanced | internal | downgrade to `chat-groq` |
| Finance | `finance-ops` | strict | confidential | block |
| Management | `leadership` | strict | confidential | alert only |
| Engineering | `product-dev` | balanced | internal | downgrade to `chat-groq` |
| Engineering | `ai-platform` | balanced | internal | alert only |

The policy uses the `pii`, `secrets` and `signatures` packs, `balanced` as the default profile, and no custom rules. The MCP catalogue registers two example servers, `tickets` (issue tracker and wiki) and `confluence` (documentation search), which the test stack's stub servers implement.

## Profiles of the whole configuration

`config/profiles/<name>/` holds an alternative configuration. A profile contains only the files that differ from `config/`; the others are taken from `config/`.

**The bank demo profile** (`config/profiles/bank/`) is a fictional Polish bank: departments such as Payments, Retail Banking, Markets and Risk, every team on the `strict` profile, and the policy with all four packs (`pii`, `pl`, `secrets`, `signatures`). It has its own `policy.yaml`, `teams.yaml`, `models.yaml` and `mcp.yaml`, and uses the shared `signatures.yaml`.

To run with it:

```
make up PROFILE=bank
```

This points `CTRL_AI_POLICY_FILE`, `CTRL_AI_TEAMS_FILE`, `CTRL_AI_MODELS_FILE` and `CTRL_AI_MCP_FILE` at the profile's files (inside the containers, `/app/config/profiles/bank/...`) for both the gateway and the admin panel. Without `make`, set those variables in `.env` instead. Gateway keys are issued per team, so keys issued under one profile belong to teams that may not exist in another.

The test suites use a third, frozen configuration in `tests/fixtures/config/`, so editing `config/` never changes a test result.
