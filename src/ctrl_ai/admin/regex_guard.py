"""Guard against regular expressions that can hang the gateway (ReDoS).

Two checks: a static one that refuses nested quantifiers such as `(a+)+` or `(.*)*`, and a
timed one that runs the pattern against adversarial 10,000-character strings in a forked
child process with a 50 ms budget per string. A child that runs over is killed.
"""

from __future__ import annotations

import multiprocessing
import re
import time

BUDGET_S = 0.050
SAMPLE_LEN = 10_000
HARD_TIMEOUT_S = 2.0

# A group that itself contains a quantifier, followed by a quantifier: (x+)+, (x*)*, (x+){2,}, (?:a|b+)*
_NESTED = re.compile(
    r"\((?:\?:)?(?:[^()\\]|\\.)*(?:[+*]|\{\d+,?\d*\})(?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,?\d*\})"
)


def static_problem(pattern: str) -> str | None:
    """A reason if the pattern has a nested quantifier, else None."""
    if _NESTED.search(pattern):
        return "nested quantifier (for example (a+)+ or (.*)*) can take exponential time"
    return None


def _samples(pattern: str) -> list[str]:
    literals = sorted({c for c in pattern if c.isalnum() or c in " -_.@/:"})[:8]
    chars = list(dict.fromkeys(["a", "1", " ", "A", "-", *literals]))
    out = []
    for c in chars:
        out.append(c * SAMPLE_LEN)
        out.append(c * (SAMPLE_LEN - 1) + "!")
    out.append(("ab" * SAMPLE_LEN)[:SAMPLE_LEN])
    return out


def _child(pattern: str, queue) -> None:
    compiled = re.compile(pattern)
    worst = 0.0
    for sample in _samples(pattern):
        start = time.perf_counter()
        compiled.search(sample)
        worst = max(worst, time.perf_counter() - start)
        if worst > BUDGET_S:
            break
    queue.put(worst)


def timed_problem(pattern: str) -> str | None:
    """Run the pattern on adversarial strings in a child process; a reason if it is too slow."""
    try:
        ctx = multiprocessing.get_context("fork")
    except ValueError:  # pragma: no cover - platforms without fork
        ctx = multiprocessing.get_context()
    queue = ctx.Queue()
    proc = ctx.Process(target=_child, args=(pattern, queue), daemon=True)
    proc.start()
    proc.join(HARD_TIMEOUT_S)
    if proc.is_alive():
        proc.kill()
        proc.join(1)
        return f"took longer than {HARD_TIMEOUT_S:.0f} s on a 10,000-character test string"
    try:
        worst = queue.get(timeout=0.5)
    except Exception:
        return "could not be tested"
    if worst > BUDGET_S:
        return f"took {worst * 1000:.0f} ms on a 10,000-character test string (budget 50 ms)"
    return None


def check(pattern: str) -> str | None:
    """None if the pattern compiles and is safe, else a human-readable reason."""
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"does not compile: {exc}"
    return static_problem(pattern) or timed_problem(pattern)
