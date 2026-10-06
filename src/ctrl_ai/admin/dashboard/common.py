"""Shared by the dashboard views: periods, filters, percentiles, cost terms, small summaries.

Cost terms used everywhere:
  spend   cost the organisation pays (rows without the free-tier `shadow` flag)
  shadow  free-tier usage valued at the provider's list price (`shadow: true`)
  total   spend + shadow: what the usage would cost at list prices. Budgets and the
          month-end forecast are compared with `total`, because free tiers do not scale.
"""

from __future__ import annotations

import calendar
import math
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

POLICY_REROUTES = {"not_approved", "banned", "deprecated", "data_class", "team_not_allowed"}
SHADOW_AI_REASONS = {"not_approved", "banned", "team_not_allowed"}


def month_bounds(today: date) -> tuple[date, date]:
    return today.replace(day=1), today.replace(day=calendar.monthrange(today.year, today.month)[1])


def parse_period(frm: str | None, to: str | None, today: date | None = None) -> tuple[date, date]:
    """Inclusive [from, to] dates; default the current month (UTC)."""
    today = today or datetime.now(UTC).date()
    start, end = month_bounds(today)
    try:
        if frm:
            start = date.fromisoformat(frm[:10])
        if to:
            end = date.fromisoformat(to[:10])
    except ValueError:
        pass
    if end < start:
        start, end = end, start
    return start, end


def apply_filters(
    records: list[dict], start: date, end: date, *, department=None, team=None, model=None, user=None
) -> list[dict]:
    lo, hi = start.isoformat(), end.isoformat()
    out = []
    for r in records:
        if not r["day"] or r["day"] < lo or r["day"] > hi:
            continue
        if department and r["department"] != department:
            continue
        if team and r["team"] != team:
            continue
        if model and model not in (r["model_routed"], r["model_requested"]):
            continue
        if user and r["user"] != user:
            continue
        out.append(r)
    return out


def percentile(values: list, p: float):
    """Nearest-rank percentile (p in 0..100); None for no values."""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    k = max(1, math.ceil(p / 100 * len(vals)))
    return vals[k - 1]


def split_cost(r: dict) -> tuple[float, float]:
    c = r["cost_usd"] or 0.0
    return (0.0, c) if r["shadow"] else (c, 0.0)


def rounded(v, n=8):
    return None if v is None else round(v, n)


def days_between(start: date, end: date) -> list[str]:
    n = (end - start).days
    return [(start + timedelta(days=i)).isoformat() for i in range(n + 1)]


def model_usage(records: list[dict], since_day: str) -> dict:
    out = defaultdict(
        lambda: {"requests": 0, "cost_usd": 0.0, "rerouted_in": 0, "rerouted_away": 0, "denied_attempts": 0}
    )
    for r in records:
        if (r["day"] or "") < since_day:
            continue
        m = out[r["model_routed"] or "unknown"]
        m["requests"] += 1
        m["cost_usd"] = round(m["cost_usd"] + (r["cost_usd"] or 0.0), 6)
        if r["model_requested"] and r["model_routed"] and r["model_requested"] != r["model_routed"]:
            m["rerouted_in"] += 1
            out[r["model_requested"]]["rerouted_away"] += 1
            if r["route_reason"] in SHADOW_AI_REASONS:
                out[r["model_requested"]]["denied_attempts"] += 1
    return dict(out)


def team_spend(records: list[dict], teams_doc: dict, today: date | None = None) -> dict:
    """This month's total (spend + shadow) per team and department, with department budgets."""
    today = today or datetime.now(UTC).date()
    start, end = month_bounds(today)
    rs = apply_filters(records, start, end)
    teams = defaultdict(float)
    deps = defaultdict(float)
    for r in rs:
        teams[r["team"]] += r["cost_usd"] or 0.0
        deps[r["department"]] += r["cost_usd"] or 0.0
    budgets = defaultdict(float)
    for t in teams_doc.get("teams", []) or []:
        b = (t.get("budget") or {}).get("monthly_usd")
        if b:
            budgets[t.get("department")] += b
    return {
        "teams": {k: {"spend_usd": round(v, 6)} for k, v in teams.items()},
        "departments": {
            k: {"spend_usd": round(deps.get(k, 0.0), 6), "budget_usd": budgets.get(k)}
            for k in set(deps) | set(budgets)
        },
    }


def filter_options(records: list[dict]) -> dict:
    return {
        "departments": sorted({r["department"] for r in records}),
        "teams": sorted({r["team"] for r in records}),
        "models": sorted({m for r in records for m in (r["model_routed"], r["model_requested"]) if m}),
        "users": sorted({r["user"] for r in records if r["user"]}),
    }


def parse_ts(ts) -> datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
