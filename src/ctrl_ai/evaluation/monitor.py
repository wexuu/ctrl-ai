"""Pair-discrepancy monitor: fixed windows, frozen reference, both directions.

A rule fires only after two consecutive eligible windows move the same signal in the same
direction past its threshold. Outages, version changes and population changes are states of
their own and break the streak; missing reviewer output never reads as "less disagreement".
The monitor never changes a live decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SIGNALS = {
    # signal: (field in the window row, absolute delta that counts as a change)
    "mean_pair_js_bits": ("mean_pair_js_bits", 0.05),
    "disagreement": ("disagreement", 0.10),
}
COVERAGE_DROP = 0.10
MIN_FAMILIES = 50
PERSISTENCE = 2
EPS = 1e-9  # exactly-at-threshold values satisfy >= despite float representation


@dataclass
class Window:
    window_id: str
    selected_pairs: int
    valid_binary_pairs: int
    families: int
    binary_coverage: float | None
    mean_pair_js_bits: float | None
    disagreement: float | None
    compatible: bool = True
    incompatible_reason: str | None = None


@dataclass
class MonitorState:
    streak_signal: str | None = None
    streak_direction: str | None = None
    streak_len: int = 0
    seen: set = field(default_factory=set)
    investigation: dict | None = None


def _change(ref: Window, cur: Window) -> tuple[str, str, float] | None:
    """The first signal past its threshold: (signal, increased|decreased, delta)."""
    for name, (attr, threshold) in SIGNALS.items():
        r, c = getattr(ref, attr), getattr(cur, attr)
        if r is None or c is None:
            continue
        delta = c - r
        if abs(delta) + EPS >= threshold:
            return name, ("increased" if delta > 0 else "decreased"), delta
    return None


def step(state: MonitorState, ref: Window, cur: Window) -> dict:
    """Evaluate one current window against the frozen reference. Idempotent per window id."""
    if cur.window_id in state.seen:
        return {
            "window_id": cur.window_id,
            "state": "already_processed",
            "investigation": state.investigation,
        }
    state.seen.add(cur.window_id)

    def reset(result: str, **extra) -> dict:
        state.streak_signal = state.streak_direction = None
        state.streak_len = 0
        return {"window_id": cur.window_id, "state": result, "investigation": state.investigation, **extra}

    if cur.selected_pairs and cur.valid_binary_pairs == 0:
        return reset("health_outage", detail="no valid reviewer pairs; discrepancy is undefined, not lower")
    if not cur.compatible:
        return reset(cur.incompatible_reason or "population_changed")
    if (
        ref.binary_coverage is not None
        and cur.binary_coverage is not None
        and ref.binary_coverage - cur.binary_coverage + EPS >= COVERAGE_DROP
    ):
        return reset("coverage_drop")
    if cur.families < MIN_FAMILIES or ref.families < MIN_FAMILIES:
        return reset(
            "insufficient_data", detail=f"{cur.families} independent families; minimum {MIN_FAMILIES}"
        )

    change = _change(ref, cur)
    if change is None:
        return reset("no_rule_fired")
    signal, direction, delta = change
    if state.streak_signal == signal and state.streak_direction == direction:
        state.streak_len += 1
    else:
        state.streak_signal, state.streak_direction, state.streak_len = signal, direction, 1
    if state.streak_len < PERSISTENCE:
        return {
            "window_id": cur.window_id,
            "state": "collecting_streak",
            "signal": signal,
            "direction": direction,
            "delta": delta,
            "investigation": state.investigation,
        }
    if state.investigation is None or state.investigation.get("status") != "open":
        state.investigation = {
            "status": "open",
            "signal": signal,
            "direction": direction,
            "opened_at_window": cur.window_id,
            "updates": [],
        }
    state.investigation["updates"].append(cur.window_id)
    return {
        "window_id": cur.window_id,
        "state": f"investigate_{direction}",
        "signal": signal,
        "direction": direction,
        "delta": delta,
        "investigation": state.investigation,
    }


def _float(v: str) -> float | None:
    return float(v) if v not in ("", None) else None


def window_from_row(row: dict) -> Window:
    return Window(
        window_id=row["window_id"],
        selected_pairs=int(row["selected_pairs"]),
        valid_binary_pairs=int(row["valid_binary_pairs"]),
        families=int(row["assumed_independent_families"]),
        binary_coverage=_float(row["binary_coverage"]),
        mean_pair_js_bits=_float(row["mean_pair_js_bits"]),
        disagreement=_float(row["disagreement"]),
        compatible=str(row["compatible"]).lower() == "true",
        incompatible_reason=row.get("incompatible_reason") or None,
    )


def run_scenarios(rows: list[dict]) -> list[dict]:
    """Run every scenario in an illustrative windows table; one result per scenario."""
    out, by = [], {}
    for row in rows:
        by.setdefault(row["scenario"], []).append(row)
    for name, items in by.items():
        ref = next(window_from_row(r) for r in items if r["window_kind"] == "reference")
        state = MonitorState()
        steps = []
        for r in items:
            if r["window_kind"] != "current":
                continue
            res = step(state, ref, window_from_row(r))
            steps.append(
                {
                    **{k: v for k, v in res.items() if k != "investigation"},
                    "expected": r.get("expected_state"),
                    "mean_pair_js_bits": _float(r["mean_pair_js_bits"]),
                    "disagreement": _float(r["disagreement"]),
                    "valid_binary_pairs": int(r["valid_binary_pairs"]),
                }
            )
        out.append(
            {
                "scenario": name,
                "mode": items[0].get("execution_mode", "illustrative_fixture"),
                "reference": {
                    "mean_pair_js_bits": ref.mean_pair_js_bits,
                    "disagreement": ref.disagreement,
                    "families": ref.families,
                },
                "windows": steps,
                "investigation": state.investigation,
            }
        )
    return out
