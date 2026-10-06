# Performance

The gateway adds two kinds of work to a model request. The deterministic half (`Engine.pre_call`) extracts the newest turn, normalises it, runs the policy rules and the rule packs, plans and applies masking, checks governance, the loop caps and the budget, and decides. The semantic half asks the classifier and, when needed, the judge, and runs alongside the model call. Only the deterministic half delays the request on its own; the semantic half's cost is the decision models' latency (see [MODELS.md](MODELS.md)).

The deterministic path typically costs **0.15 to 0.65 ms per request** on one CPU core: about 0.15 ms for a short prompt and about 0.5 to 0.65 ms for 20 kB of prompt or tool output.

## The benchmark

`scripts/bench_precall.py` (`make bench`) builds an engine from the frozen test configuration in `tests/fixtures/config` (policy with every rule pack, teams, catalogue, signature feed), with a static classifier and judge and a masking secret. There is no network, no Redis (the shared counters fail open, as they would with Redis down) and no LiteLLM. For each request shape it times `pre_call` (the deterministic half) and `evaluate` (pre-call, the static classifier and judge, and the audit row written to a temporary file): a warm-up, then `--iterations` calls (300 by default). The newest text differs on every call, so no cache keyed on the text can answer for an earlier call. `peak KiB` is the most memory one call holds at once beyond what it started with (tracemalloc, median of 20 calls); `--json` prints the same numbers as JSON.

| Shape | What the request contains |
|---|---|
| short prompt | one user message of about 60 characters |
| long prompt | one user message of 20,000 characters of ordinary prose |
| tool result | a tool call and its 20,000-character output (a file listing) as the newest turn |
| masked identifiers | a prompt with an IBAN, a PESEL, an e-mail address and a phone number, rewritten on the external route |
| claude code | a Claude Code request: a `<system-reminder>` block before the prompt, Claude Code's headers |

```
make bench                      # or: .venv/bin/python scripts/bench_precall.py --iterations 1000
.venv/bin/python scripts/bench_precall.py --json
```

The numbers below come from a 4-vCPU virtual machine (`QEMU Virtual CPU version 2.5+`), Python 3.13. Absolute numbers depend on the machine; compare runs made on the same one.

## Results

| Shape | Stage | p50 ms | p95 ms | max ms | peak KiB |
|---|---|---:|---:|---:|---:|
| short prompt | pre_call | 0.146 | 0.182 | 0.235 | 8.2 |
| short prompt | evaluate | 0.351 | 0.490 | 0.615 | 11.5 |
| long prompt | pre_call | 0.480 | 0.589 | 1.067 | 8.2 |
| long prompt | evaluate | 0.740 | 0.924 | 1.385 | 11.4 |
| tool result | pre_call | 0.658 | 0.795 | 0.988 | 8.3 |
| tool result | evaluate | 0.860 | 0.981 | 1.258 | 11.7 |
| masked identifiers | pre_call | 0.578 | 0.728 | 0.814 | 10.9 |
| masked identifiers | evaluate | 0.773 | 0.884 | 1.098 | 14.5 |
| claude code | pre_call | 0.182 | 0.228 | 0.323 | 8.4 |
| claude code | evaluate | 0.389 | 0.476 | 0.576 | 11.8 |

## Where the time goes

The profile of the deterministic path (`python -m cProfile` over the benchmark) is flat: the pattern scans of the policy rules, the secrets and signature packs, the identifier detectors over the digit runs, one `os.stat` per configuration file (policy, teams, catalogue, signature feed), masking's encryption of the surrogate map, and building the context and the row. Three implementation choices keep the scans cheap on long texts:

- **No leading look-behind.** A pattern that starts with a look-behind makes Python's `re` try every position of the text; one that starts with a character class or a literal lets it jump to the candidates. The IBAN and international phone candidates match without their look-behind, and `detectors._finditer` checks the preceding character in code, which gives exactly the same matches about four times faster.
- **Alternations searched branch by branch.** A signature such as `pickle.loads(` or `torch.load(...)` occurs exactly when one of its alternatives does; searching each alternative on its own lets `re` jump to its literal, about seven times faster than trying the whole alternation at every position. The compiled rules are built once per signature feed.
- **One detection pass per text per request.** The digit windows are found by a pattern that skips runs too short to hold an identifier; each text is scanned by the identifier detectors once per request (`detectors.Scans`), shared by the identifier rules and by masking, and dropped when the pre-call step ends, so no request text stays in the process after the request. The teams and the catalogue are read once per request.

## Reference: the same checks without these choices

For comparison, the same benchmark on the same machine with leading look-behinds, whole alternations, signature rules built per request and the detectors keyed on the text:

| Shape | Stage | p50 ms | p95 ms | max ms | peak KiB |
|---|---|---:|---:|---:|---:|
| short prompt | pre_call | 0.188 | 0.239 | 0.402 | 11.2 |
| short prompt | evaluate | 0.397 | 0.491 | 0.861 | 11.7 |
| long prompt | pre_call | 0.992 | 1.180 | 1.724 | 11.4 |
| long prompt | evaluate | 1.210 | 1.401 | 1.935 | 11.7 |
| tool result | pre_call | 1.212 | 1.500 | 2.000 | 11.6 |
| tool result | evaluate | 1.405 | 1.699 | 2.097 | 11.8 |
| masked identifiers | pre_call | 0.665 | 1.090 | 1.231 | 16.2 |
| masked identifiers | evaluate | 0.830 | 1.060 | 1.599 | 16.4 |
| claude code | pre_call | 0.231 | 0.310 | 0.415 | 11.5 |
| claude code | evaluate | 0.437 | 0.516 | 0.625 | 11.9 |
