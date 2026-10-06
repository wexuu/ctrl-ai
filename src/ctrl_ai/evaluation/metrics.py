"""Pure metric functions for the Jev trust report.

No model calls, no I/O. Every function takes plain numbers and returns plain dictionaries,
so the dashboard, the worker and the tests share one definition. Undefined values are
``None`` with a reason, never zero.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

CLIP = 1e-6
BIN_EDGES = (0.0, 0.2, 0.4, 0.6, 0.8, 1.0)
DEFAULT_CUTOFF = 0.5


class InvalidScore(ValueError):
    """A score or label that is not a finite number in its allowed range."""


def check_probability(p) -> float:
    if isinstance(p, bool) or not isinstance(p, (int, float)) or not math.isfinite(p) or not 0.0 <= p <= 1.0:
        raise InvalidScore(f"probability out of range: {p!r}")
    return float(p)


def check_label(y) -> int:
    if y not in (0, 1) or isinstance(y, bool):
        raise InvalidScore(f"label must be 0 or 1: {y!r}")
    return int(y)


def _weights(n: int, weights: Sequence[float] | None) -> list[float]:
    if weights is None:
        return [1.0] * n
    if len(weights) != n:
        raise ValueError("weights and scores differ in length")
    out = []
    for w in weights:
        if isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w) or w <= 0:
            raise InvalidScore(f"weight must be a positive finite number: {w!r}")
        out.append(float(w))
    return out


def log_loss(p: Sequence[float], y: Sequence[int], weights: Sequence[float] | None = None) -> dict:
    """Weighted binary cross entropy in nats. Only the loss term clips p into [1e-6, 1-1e-6]."""
    ps, ys = [check_probability(v) for v in p], [check_label(v) for v in y]
    if len(ps) != len(ys):
        raise ValueError("scores and labels differ in length")
    ws = _weights(len(ps), weights)
    if not ps:
        return {"value": None, "reason": "no_evaluated_cases", "clipped": 0}
    total, clipped = 0.0, 0
    for pi, yi, wi in zip(ps, ys, ws, strict=False):
        pc = min(1 - CLIP, max(CLIP, pi))
        clipped += pc != pi
        total += wi * (-(yi * math.log(pc)) - (1 - yi) * math.log(1 - pc))
    return {"value": total / sum(ws), "reason": None, "clipped": clipped}


def brier(p: Sequence[float], y: Sequence[int], weights: Sequence[float] | None = None) -> dict:
    ps, ys = [check_probability(v) for v in p], [check_label(v) for v in y]
    ws = _weights(len(ps), weights)
    if not ps:
        return {"value": None, "reason": "no_evaluated_cases"}
    return {
        "value": sum(w * (a - b) ** 2 for a, b, w in zip(ps, ys, ws, strict=False)) / sum(ws),
        "reason": None,
    }


def bin_index(p: float) -> int:
    """Fixed bins [0,.2) [.2,.4) [.4,.6) [.6,.8) [.8,1]."""
    p = check_probability(p)
    for i in range(len(BIN_EDGES) - 2):
        if p < BIN_EDGES[i + 1]:
            return i
    return len(BIN_EDGES) - 2


def reliability(p: Sequence[float], y: Sequence[int], weights: Sequence[float] | None = None) -> dict:
    """Reliability bins and ECE. Empty bins have null means and add nothing to ECE."""
    ps, ys = [check_probability(v) for v in p], [check_label(v) for v in y]
    ws = _weights(len(ps), weights)
    bins = []
    for i in range(len(BIN_EDGES) - 1):
        bins.append({"lo": BIN_EDGES[i], "hi": BIN_EDGES[i + 1], "n": 0, "w": 0.0, "_wp": 0.0, "_wy": 0.0})
    for pi, yi, wi in zip(ps, ys, ws, strict=False):
        b = bins[bin_index(pi)]
        b["n"] += 1
        b["w"] += wi
        b["_wp"] += wi * pi
        b["_wy"] += wi * yi
    W = sum(ws)
    ece = 0.0 if W else None
    for b in bins:
        wp, wy = b.pop("_wp"), b.pop("_wy")
        if b["w"]:
            b["predicted_mean"], b["observed_rate"] = wp / b["w"], wy / b["w"]
            ece += (b["w"] / W) * abs(b["predicted_mean"] - b["observed_rate"])
        else:
            b["predicted_mean"] = b["observed_rate"] = None
        b["sparse"] = b["n"] < 20
    return {
        "bins": bins,
        "ece": ece,
        "ece_pp": None if ece is None else 100 * ece,
        "reason": None if W else "no_evaluated_cases",
    }


def _ratio(num: float, den: float, reason: str) -> dict:
    return {"value": num / den, "reason": None} if den else {"value": None, "reason": reason}


def confusion(
    p: Sequence[float],
    y: Sequence[int],
    cutoff: float = DEFAULT_CUTOFF,
    weights: Sequence[float] | None = None,
) -> dict:
    """Weighted TP/FN/FP/TN at an offline audit cutoff (positive if p >= cutoff)."""
    ps, ys = [check_probability(v) for v in p], [check_label(v) for v in y]
    ws = _weights(len(ps), weights)
    c = {"tp": 0.0, "fn": 0.0, "fp": 0.0, "tn": 0.0}
    for pi, yi, wi in zip(ps, ys, ws, strict=False):
        flagged = pi >= cutoff
        c[("tp" if flagged else "fn") if yi else ("fp" if flagged else "tn")] += wi
    return {
        "cutoff": cutoff,
        "cells": c,
        "recall": _ratio(c["tp"], c["tp"] + c["fn"], "no_positive_labels"),
        "fnr": _ratio(c["fn"], c["tp"] + c["fn"], "no_positive_labels"),
        "fpr": _ratio(c["fp"], c["fp"] + c["tn"], "no_negative_labels"),
        "precision": _ratio(c["tp"], c["tp"] + c["fp"], "no_predicted_positives"),
    }


def agreement(a: Sequence[int], b: Sequence[int], weights: Sequence[float] | None = None) -> dict:
    """Four-cell agreement between two binary verdicts (a = Jev, b = reviewer)."""
    av, bv = [check_label(v) for v in a], [check_label(v) for v in b]
    ws = _weights(len(av), weights)
    n = {"n00": 0.0, "n01": 0.0, "n10": 0.0, "n11": 0.0}
    for x, z, w in zip(av, bv, ws, strict=False):
        n[f"n{x}{z}"] += w
    N = sum(ws)
    pos_den = 2 * n["n11"] + n["n01"] + n["n10"]
    return {
        "cells": n,
        "n": N,
        "agreement": _ratio(n["n00"] + n["n11"], N, "no_valid_pairs"),
        "disagreement": _ratio(n["n01"] + n["n10"], N, "no_valid_pairs"),
        "jev_clear_reviewer_flagged": _ratio(n["n01"], N, "no_valid_pairs"),
        "jev_flagged_reviewer_clear": _ratio(n["n10"], N, "no_valid_pairs"),
        "positive_agreement": _ratio(2 * n["n11"], pos_den, "no_positive_verdicts"),
    }


def _kl2(p: Sequence[float], m: Sequence[float]) -> float:
    return sum(pi * math.log2(pi / mi) for pi, mi in zip(p, m, strict=False) if pi > 0)


def jsd_bits(p: float, q: float) -> float:
    """Jensen-Shannon divergence in bits between Bernoulli(p) and Bernoulli(q). Range [0,1]."""
    p, q = check_probability(p), check_probability(q)
    P, Q = (p, 1 - p), (q, 1 - q)
    M = tuple((x + z) / 2 for x, z in zip(P, Q, strict=False))
    return max(0.0, 0.5 * _kl2(P, M) + 0.5 * _kl2(Q, M))


def numeric_divergence(
    p: Sequence[float], q: Sequence[float], weights: Sequence[float] | None = None
) -> dict:
    """Weighted mean per-case JSD, mean absolute gap and signed gap (q - p)."""
    ps, qs = [check_probability(v) for v in p], [check_probability(v) for v in q]
    ws = _weights(len(ps), weights)
    if not ps:
        return {
            "mean_jsd_bits": None,
            "mean_abs_gap": None,
            "signed_gap": None,
            "per_case": [],
            "reason": "no_valid_numeric_pairs",
        }
    W = sum(ws)
    per = [jsd_bits(a, b) for a, b in zip(ps, qs, strict=False)]
    return {
        "mean_jsd_bits": sum(w * j for w, j in zip(ws, per, strict=False)) / W,
        "mean_abs_gap": sum(w * abs(a - b) for a, b, w in zip(ps, qs, ws, strict=False)) / W,
        "signed_gap": sum(w * (b - a) for a, b, w in zip(ps, qs, ws, strict=False)) / W,
        "per_case": per,
        "reason": None,
    }


def wilson(successes: int, n: int, z: float = 1.959963984540054) -> dict:
    """Wilson interval for an unweighted independent proportion."""
    if n <= 0:
        return {"lo": None, "hi": None, "reason": "no_cases"}
    ph = successes / n
    den = 1 + z * z / n
    centre = (ph + z * z / (2 * n)) / den
    half = z * math.sqrt(ph * (1 - ph) / n + z * z / (4 * n * n)) / den
    return {"lo": max(0.0, centre - half), "hi": min(1.0, centre + half), "reason": None}
