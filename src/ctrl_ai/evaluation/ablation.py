"""Bounded same-model span ablation: which checked text moved Jev's score.

For one target (case, Jev criterion): score the baseline, delete each of at most four
contiguous candidate segments, then delete two distinct, seeded, length-matched control spans
that do not overlap the chosen candidate. The candidate is "supported" only if its drop is large and
clearly beats the controls. At most seven scoring calls per target. Offsets are Unicode code
points, start inclusive, end exclusive, on the exact checked text.
"""

from __future__ import annotations

import random
import re
from collections.abc import Awaitable, Callable

MAX_CANDIDATES = 4
N_CONTROLS = 2
LENGTH_TOLERANCE = 0.20
MIN_DELTA = 0.10
MIN_MARGIN = 0.05

Scorer = Callable[[str], Awaitable[float | None]]

_SENTENCE = re.compile(r"[^.!?]+(?:[.!?]+|$)\s*")


def segments(text: str) -> list[tuple[int, int]]:
    """Sentence spans; more than four are grouped into four contiguous chunks (frozen rule)."""
    spans = [(m.start(), m.end()) for m in _SENTENCE.finditer(text) if m.group(0).strip()]
    if not spans:
        return [(0, len(text))] if text else []
    if len(spans) <= MAX_CANDIDATES:
        return spans
    size = -(-len(spans) // MAX_CANDIDATES)
    return [(spans[i][0], spans[min(i + size, len(spans)) - 1][1]) for i in range(0, len(spans), size)]


def delete(text: str, span: tuple[int, int]) -> str:
    return text[: span[0]] + text[span[1] :]


def control_spans(text: str, avoid: tuple[int, int], seed: int) -> list[tuple[int, int]] | None:
    """Two distinct spans that do not overlap ``avoid`` (they may overlap each other), length within
    +-20% of it. None if the text outside ``avoid`` is too short."""
    length = avoid[1] - avoid[0]
    lo, hi = max(1, int(length * (1 - LENGTH_TOLERANCE))), int(length * (1 + LENGTH_TOLERANCE))
    rng = random.Random(seed)
    free = [(0, avoid[0]), (avoid[1], len(text))]
    chosen: list[tuple[int, int]] = []
    for _ in range(200):
        if len(chosen) == N_CONTROLS:
            break
        a, b = rng.choice(free)
        want = min(length, b - a)
        if want < lo:
            continue
        want = min(want, hi)
        start = rng.randint(a, b - want)
        span = (start, start + want)
        if span not in chosen:
            chosen.append(span)
    return sorted(chosen) if len(chosen) == N_CONTROLS else None


async def explain(
    text: str, score: Scorer, *, cutoff: float = 0.5, seed: int = 7, baseline: float | None = None
) -> dict:
    """Run the bounded ablation. Every outcome, including failures, is returned with its reason."""
    calls = 0
    out: dict = {
        "candidates": [],
        "controls": [],
        "supported": False,
        "status": "inconclusive",
        "reason": None,
        "baseline": baseline,
        "calls": 0,
    }

    async def s(t: str) -> float | None:
        nonlocal calls
        calls += 1
        return await score(t)

    if baseline is None:
        baseline = await s(text)
        out["baseline"] = baseline
    if baseline is None:
        out.update(status="failed", reason="baseline_unavailable", calls=calls)
        return out
    if baseline < cutoff:
        out.update(status="not_applicable", reason="baseline_below_cutoff", calls=calls)
        return out
    segs = segments(text)
    if len(segs) < 2:
        out.update(reason="single_segment_no_controls", calls=calls)
        return out
    for span in segs:
        v = await s(delete(text, span))
        out["candidates"].append(
            {
                "start": span[0],
                "end": span[1],
                "score": v,
                "delta": None if v is None else round(baseline - v, 6),
            }
        )
    valid = [c for c in out["candidates"] if c["delta"] is not None]
    if not valid:
        out.update(status="failed", reason="candidate_scoring_failed", calls=calls)
        return out
    best = max(valid, key=lambda c: c["delta"])
    out["hypothesis"] = {"start": best["start"], "end": best["end"], "delta": best["delta"]}
    ctrls = control_spans(text, (best["start"], best["end"]), seed)
    if ctrls is None:
        out.update(reason="no_length_matched_controls", calls=calls)
        return out
    for span in ctrls:
        v = await s(delete(text, span))
        out["controls"].append(
            {
                "start": span[0],
                "end": span[1],
                "score": v,
                "delta": None if v is None else round(baseline - v, 6),
            }
        )
    cdeltas = [c["delta"] for c in out["controls"]]
    if any(d is None for d in cdeltas):
        out.update(status="failed", reason="control_scoring_failed", calls=calls)
        return out
    adjusted = best["delta"] - sum(cdeltas) / len(cdeltas)
    out["adjusted_effect"] = round(adjusted, 6)
    supported = best["delta"] >= MIN_DELTA and best["delta"] - max(cdeltas) >= MIN_MARGIN
    out.update(
        supported=supported,
        status="supported" if supported else "unsupported",
        reason=None if supported else "effect_not_above_controls",
        calls=calls,
    )
    return out
