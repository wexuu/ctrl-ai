"""The operations view: latency, errors, fallbacks and throughput."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta

from ctrl_ai.admin.dashboard.common import (
    percentile,
    rounded,
)


def _error_class(r: dict) -> str | None:
    """A gateway or provider error, not a policy outcome (blocks and throttles are not errors)."""
    if r["decision"] in ("block", "throttle"):
        return None
    if r["error"]:
        return r["error"].split(":")[0][:40] if ":" in r["error"] else r["error"][:40]
    if r["status"] == "failure":
        return "failure"
    return None


def operations(records: list[dict], now: datetime | None = None, prometheus: dict | None = None) -> dict:
    now = now or datetime.now(UTC)
    recent_cut = (now - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%S")
    recent = [r for r in records if (r["ts"] or "") >= recent_cut]
    totals = [r["total_ms"] for r in records]
    guards = [r["guard_ms"] for r in records]
    errors = Counter(c for c in (_error_class(r) for r in records) if c)
    with_usage = [r for r in records if r["has_usage"]]
    jev = Counter(r["jev_status"] for r in records if r["jev_status"] in ("ok", "unavailable", "error"))
    judge = Counter("ok" if r["judge_status"] == "ok" else "down" for r in records if r["judge_status"])
    unknown = [r for r in records if r["has_usage"] and r["cost_source"] == "unknown"]
    # Buckets: hourly when the data spans two days or less, else daily.
    span_days = 0
    if records and records[0]["ts"] and records[-1]["ts"]:
        span_days = (date.fromisoformat(records[-1]["day"]) - date.fromisoformat(records[0]["day"])).days
    width = 13 if span_days <= 2 else 10
    buckets = defaultdict(list)
    for r in records:
        if r["ts"]:
            buckets[r["ts"][:width]].append(r)
    series = []
    for b in sorted(buckets):
        rs = buckets[b]
        series.append(
            {
                "bucket": b + (":00" if width == 13 else ""),
                "requests": len(rs),
                "p50_total": percentile([x["total_ms"] for x in rs], 50),
                "p95_total": percentile([x["total_ms"] for x in rs], 95),
                "p50_guard": percentile([x["guard_ms"] for x in rs], 50),
                "p95_guard": percentile([x["guard_ms"] for x in rs], 95),
                "errors": dict(Counter(c for c in (_error_class(x) for x in rs) if c)),
                "fallbacks": sum(1 for x in rs if x["fallback_used"]),
            }
        )
    p50_total, p50_guard = percentile(totals, 50), percentile(guards, 50)
    p50_jev = percentile([r["jev_latency_ms"] for r in records if r["jev_status"] == "ok"], 50)
    return {
        "kpis": {
            "rpm_15min": rounded(len(recent) / 15, 2),
            "requests": len(records),
            "p50_total_ms": p50_total,
            "p95_total_ms": percentile(totals, 95),
            "p50_guard_ms": p50_guard,
            "p95_guard_ms": percentile(guards, 95),
            "error_rate": rounded(sum(errors.values()) / len(records), 4) if records else None,
            "fallback_rate": rounded(sum(1 for r in with_usage if r["fallback_used"]) / len(with_usage), 4)
            if with_usage
            else None,
            "jev_availability": rounded(jev["ok"] / sum(jev.values()), 4) if jev else None,
            "judge_availability": rounded(judge["ok"] / sum(judge.values()), 4) if judge else None,
            "unknown_price_requests": len(unknown),
            "unknown_price_tokens": sum(r["input_tokens"] + r["output_tokens"] for r in unknown),
        },
        "series": series,
        "errors": dict(sorted(errors.items())),
        "jev_latency": _hist([r["jev_latency_ms"] for r in records if r["jev_status"] == "ok"]),
        "judge_latency": _hist([r["judge_latency_ms"] for r in records if r["judge_status"]]),
        "fallbacks": [
            {"ts": r["ts"], "requested": r["model_requested"], "routed": r["model_routed"], "team": r["team"]}
            for r in records
            if r["fallback_used"]
        ][-50:],
        "time_split": {
            "gateway_checks_ms": p50_guard,
            "semantic_ms": p50_jev,
            "model_ms": max(0.0, p50_total - p50_guard)
            if p50_total is not None and p50_guard is not None
            else None,
            "note": "median per request; the semantic check runs in parallel with the rules, inside the gateway checks",
        },
        "prometheus": prometheus,
    }


LAT_EDGES = (50, 100, 200, 400, 800, 1600, 3200, 6400)


def _hist(values: list) -> list[dict]:
    vals = [v for v in values if v is not None]
    counts = [0] * (len(LAT_EDGES) + 1)
    for v in vals:
        i = 0
        while i < len(LAT_EDGES) and v >= LAT_EDGES[i]:
            i += 1
        counts[i] += 1
    labels = (
        [f"<{LAT_EDGES[0]}"]
        + [f"{LAT_EDGES[i]}–{LAT_EDGES[i + 1]}" for i in range(len(LAT_EDGES) - 1)]
        + [f"≥{LAT_EDGES[-1]}"]
    )
    shorts = ["0"] + [str(e) for e in LAT_EDGES]
    return [
        {"label": label + " ms", "short": short, "value": c}
        for label, short, c in zip(labels, shorts, counts, strict=False)
    ]
