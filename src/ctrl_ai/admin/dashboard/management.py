"""The management view: spend, budgets, forecast, adoption and governance per team and model."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, date, datetime

from ctrl_ai.admin.config_checks import find_model
from ctrl_ai.admin.dashboard.common import (
    days_between,
    month_bounds,
    rounded,
    split_cost,
)
from ctrl_ai.admin.records import UNATTRIBUTED


def management(
    records: list[dict], start: date, end: date, teams_doc: dict, models_doc: dict, today: date | None = None
) -> dict:
    today = today or datetime.now(UTC).date()
    teams = {t.get("id"): t for t in teams_doc.get("teams", []) or [] if isinstance(t, dict)}
    deps = {d.get("id"): d.get("name") for d in teams_doc.get("departments", []) or [] if isinstance(d, dict)}
    status_of = _model_status(models_doc)
    spend = shadow = 0.0
    approved_total = 0.0
    by_dep = defaultdict(lambda: {"spend": 0.0, "shadow": 0.0, "requests": 0})
    by_team = defaultdict(
        lambda: {"spend": 0.0, "shadow": 0.0, "requests": 0, "tokens_in": 0, "tokens_out": 0, "users": set()}
    )
    by_model = defaultdict(lambda: {"spend": 0.0, "shadow": 0.0, "requests": 0})
    daily = defaultdict(lambda: defaultdict(float))
    daily_users = defaultdict(set)
    daily_req = Counter()
    users = Counter()
    for r in records:
        s, sh = split_cost(r)
        spend += s
        shadow += sh
        if status_of(r["model_routed"]) == "approved":
            approved_total += s + sh
        for agg, key in (
            (by_dep, r["department"]),
            (by_team, r["team"]),
            (by_model, r["model_routed"] or "unknown"),
        ):
            agg[key]["spend"] += s
            agg[key]["shadow"] += sh
            agg[key]["requests"] += 1
        bt = by_team[r["team"]]
        bt["tokens_in"] += r["input_tokens"]
        bt["tokens_out"] += r["output_tokens"]
        if r["user"]:
            bt["users"].add(r["user"])
            daily_users[r["day"]].add(r["user"])
            users[r["user"]] += 1
        daily[r["day"]][r["department"]] += s + sh
        daily_req[r["day"]] += 1
    total = spend + shadow
    # Budgets: teams in the filtered set (all teams when no team/department filter applies).
    team_budget = {tid: (t.get("budget") or {}).get("monthly_usd") for tid, t in teams.items()}
    dep_budget = defaultdict(float)
    for tid, t in teams.items():
        budget = team_budget.get(tid)
        if budget:
            dep_budget[t.get("department")] += budget
    # Forecast: only meaningful for a period inside the current month.
    m_start, m_end = month_bounds(today)
    forecast = None
    if start >= m_start and end <= m_end and today >= start:
        elapsed = (min(today, end) - m_start).days + 1
        forecast = total / elapsed * m_end.day if elapsed > 0 else None
    dep_ids = sorted(
        set(by_dep) | set(deps),
        key=lambda k: -(by_dep[k]["spend"] + by_dep[k]["shadow"]) if k in by_dep else 0,
    )
    departments = []
    for k in dep_ids:
        v = by_dep.get(k, {"spend": 0.0, "shadow": 0.0, "requests": 0})
        b = dep_budget.get(k) or None
        t_ = v["spend"] + v["shadow"]
        departments.append(
            {
                "id": k,
                "name": deps.get(k, k),
                "spend": rounded(v["spend"]),
                "shadow": rounded(v["shadow"]),
                "total": rounded(t_),
                "requests": v["requests"],
                "budget": b,
                "utilisation": rounded(t_ / b, 4) if b else None,
            }
        )
    team_rows = []
    for k in sorted(set(by_team) | set(teams), key=str):
        v = by_team.get(k) or {
            "spend": 0.0,
            "shadow": 0.0,
            "requests": 0,
            "tokens_in": 0,
            "tokens_out": 0,
            "users": set(),
        }
        b = team_budget.get(k)
        t_ = v["spend"] + v["shadow"]
        meta = teams.get(k, {})
        team_rows.append(
            {
                "id": k,
                "name": meta.get("name", k),
                "department": meta.get("department")
                or next((r["department"] for r in records if r["team"] == k), UNATTRIBUTED),
                "requests": v["requests"],
                "tokens_in": v["tokens_in"],
                "tokens_out": v["tokens_out"],
                "users": len(v["users"]),
                "spend": rounded(v["spend"]),
                "shadow": rounded(v["shadow"]),
                "total": rounded(t_),
                "budget": b,
                "utilisation": rounded(t_ / b, 4) if b else None,
                "default_model": meta.get("default_model"),
            }
        )
    model_rows = [
        {
            "model": k,
            "status": status_of(k),
            "requests": v["requests"],
            "spend": rounded(v["spend"]),
            "shadow": rounded(v["shadow"]),
            "total": rounded(v["spend"] + v["shadow"]),
        }
        for k, v in by_model.items()
    ]
    # Up to today, or to the newest record when the clocks disagree (UTC vs local midnight).
    last = max([date.fromisoformat(r["day"]) for r in records if r["day"]] + [today, start])
    days = days_between(start, min(end, last))
    daily_rows = [
        {
            "day": d,
            "by_department": {k: rounded(v) for k, v in daily.get(d, {}).items()},
            "total": rounded(sum(daily.get(d, {}).values())),
            "requests": daily_req.get(d, 0),
            "active_users": len(daily_users.get(d, ())),
        }
        for d in days
    ]
    budget_total = sum(b for b in team_budget.values() if b)
    return {
        "kpis": {
            "spend": rounded(spend),
            "shadow": rounded(shadow),
            "total": rounded(total),
            "forecast": rounded(forecast),
            "budget_total": budget_total or None,
            "requests": len(records),
            "active_users": len({r["user"] for r in records if r["user"]}),
            "active_teams": len({r["team"] for r in records if r["team"] != UNATTRIBUTED}),
            "approved_share": rounded(approved_total / total, 4) if total else None,
        },
        "departments": departments,
        "teams": team_rows,
        "models_by_cost": sorted(model_rows, key=lambda m: (-(m["total"] or 0), m["model"]))[:10],
        "models_by_requests": sorted(model_rows, key=lambda m: (-m["requests"], m["model"]))[:10],
        "daily": daily_rows,
        "forecast_daily": rounded(forecast / m_end.day, 6) if forecast else None,
        "top_users": [
            {"user": u, "requests": n} for u, n in sorted(users.items(), key=lambda x: (-x[1], x[0]))[:10]
        ],
    }


def _model_status(models_doc: dict):
    def status(name):
        if not name:
            return None
        model = find_model(models_doc, name)
        return model.get("status") if model is not None else "unlisted"

    return status
