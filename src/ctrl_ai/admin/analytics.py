"""Dashboard data layer: the audit log turned into management, security and operations figures.

Pure Python (no FastAPI), host-testable and deterministic. The audit log is append-only: it
is read incrementally (only the bytes added since the last read) and at most the newest
MAX_ROWS rows are kept. Version-1 and version-2 rows are both accepted;
missing identity becomes "unattributed".

Cost terms used everywhere:
  spend   cost the organisation pays (rows without the free-tier `shadow` flag)
  shadow  free-tier usage valued at the provider's list price (`shadow: true`)
  total   spend + shadow: what the usage would cost at list prices. Budgets and the
          month-end forecast are compared with `total`, because free tiers do not scale.
"""

from __future__ import annotations

import calendar
import json
import math
import os
import threading
from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from datetime import UTC, date, datetime, timedelta

from ctrl_ai.detect.packs import PACK_IDS

MAX_ROWS = 500_000
UNATTRIBUTED = "unattributed"
POLICY_REROUTES = {"not_approved", "banned", "deprecated", "data_class", "team_not_allowed"}
SHADOW_AI_REASONS = {"not_approved", "banned", "team_not_allowed"}
MASK_TYPES = ("iban", "pesel", "nip", "card", "email", "phone")
PACKS = (*PACK_IDS, "custom")
EXPORT_FIELDS = (
    "request_id",
    "ts",
    "team",
    "department",
    "user",
    "key_id",
    "profile",
    "endpoint",
    "model_requested",
    "model_routed",
    "provider",
    "decision",
    "rule",
    "mode",
    "would_block",
    "flagged",
    "route_reason",
    "data_class_detected",
    "findings",
    "masked",
    "semantic_source",
    "semantic_score",
    "semantic_action",
    "semantic_reason",
    "jev_status",
    "jev_score",
    "judge_status",
    "judge_score",
    "judge_category",
    "break_glass_id",
    "status",
    "error",
    "input_tokens",
    "output_tokens",
    "cost_usd",
    "cost_source",
    "shadow",
    "fallback_used",
    "guard_ms",
    "total_ms",
    "policy_version",
)


# ---------------------------------------------------------------- reading


class LogReader:
    """Incremental reader of an append-only JSON-lines file; keeps the newest MAX_ROWS rows."""

    def __init__(self, path: str, max_rows: int = MAX_ROWS):
        self.path = path
        self.rows: deque = deque(maxlen=max_rows)
        self.offset = 0
        self.inode = None
        self.version = 0  # bumps whenever rows change
        self.lock = threading.Lock()

    def refresh(self) -> bool:
        """Read new complete lines; True when rows changed. A replaced or shrunk file is re-read."""
        with self.lock:
            try:
                st = os.stat(self.path)
            except OSError:
                if self.rows:
                    self.rows.clear()
                    self.offset, self.inode = 0, None
                    self.version += 1
                    return True
                return False
            if self.inode != st.st_ino or st.st_size < self.offset:
                self.rows.clear()
                self.offset, self.inode = 0, st.st_ino
                self.version += 1
            if st.st_size == self.offset:
                return False
            with open(self.path, "rb") as handle:
                handle.seek(self.offset)
                data = handle.read(st.st_size - self.offset)
            end = data.rfind(b"\n")
            if end < 0:
                return False  # only a line still being written
            for line in data[:end].split(b"\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    self.rows.append(row)
            self.offset += end + 1
            self.version += 1
            return True


_READERS: dict = {}
_CACHE: dict = {}
_LOCK = threading.Lock()


def _reader(path: str) -> LogReader:
    with _LOCK:
        if path not in _READERS:
            _READERS[path] = LogReader(path)
        return _READERS[path]


def dataset(path: str) -> dict:
    """Joined records, tool rows and break-glass rows; cached until the file changes."""
    r = _reader(path)
    r.refresh()
    key = (path, r.inode, r.version)
    cached = _CACHE.get(path)
    if cached and cached[0] == key:
        return cached[1]
    data = build_dataset(list(r.rows))
    _CACHE[path] = (key, data)
    return data


# ---------------------------------------------------------------- joining


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _day(ts) -> str | None:
    return ts[:10] if isinstance(ts, str) and len(ts) >= 10 else None


def build_record(rid: str | None, rows: list[dict]) -> dict:
    """One normalised record per request from its decision and usage rows (v1 or v2)."""
    decisions = [r for r in rows if r.get("type") == "decision"]
    usages = [r for r in rows if r.get("type") == "usage"]
    d = decisions[-1] if decisions else {}
    first = decisions[0] if decisions else {}
    # A provider fallback gives two usage rows under one request id: a failure with 0 tokens,
    # then the success from the fallback model. The success row is the one that counts.
    successes = [r for r in usages if r.get("status") == "success"]
    u = successes[-1] if successes else (usages[-1] if usages else {})
    ts = first.get("ts") or u.get("ts")
    pick = lambda k: d.get(k) if d.get(k) is not None else u.get(k)  # noqa: E731
    cost = _num(u.get("cost_usd"))
    cost_source = u.get("cost_source") or ("litellm" if cost is not None else "unknown")
    semantic = d.get("semantic") if isinstance(d.get("semantic"), dict) else None
    jev = d.get("jev")
    jev = jev if isinstance(jev, dict) else {}
    judge = d.get("judge") if isinstance(d.get("judge"), dict) else None
    if semantic is None and jev:
        # v1: Jev only observed; its attack score is the semantic score.
        semantic = {
            "source": "jev" if jev.get("status") == "ok" else None,
            "score": _num(jev.get("attack")),
            "action": "observe",
            "reason": None,
        }
    semantic = semantic or {}
    model_requested = d.get("model_requested") or u.get("model_requested") or d.get("model") or u.get("model")
    model_routed = u.get("model_routed") or d.get("model_routed") or u.get("model") or d.get("model")
    if u.get("fallback_used") and u.get("model"):
        # After a fallback, A's usage row keeps the gateway's target in model_routed and the model
        # that actually served (and was priced) in model; spend belongs to the serving model.
        model_routed = u["model"]
    findings = d.get("findings") if isinstance(d.get("findings"), list) else []
    if not findings and d.get("rule") and d.get("v") is None:
        findings = [
            {"rule": d.get("rule"), "pack": "custom", "source": "prompt", "action": "block", "severity": None}
        ]
    masked = d.get("masked")
    masked = masked if isinstance(masked, dict) else {}
    bg = d.get("break_glass") if isinstance(d.get("break_glass"), dict) else None
    error = u.get("error") or d.get("error")
    return {
        "request_id": rid,
        "ts": ts,
        "day": _day(ts),
        "v": d.get("v") or u.get("v") or 1,
        "endpoint": pick("endpoint"),
        "team": pick("team") or UNATTRIBUTED,
        "department": pick("department") or UNATTRIBUTED,
        "user": pick("user"),
        "key_id": pick("key_id"),
        "profile": d.get("profile"),
        "model_requested": model_requested,
        "model_routed": model_routed,
        "provider": u.get("provider"),
        "decision": d.get("decision") or ("allow" if u else None),
        "rule": d.get("rule"),
        "mode": d.get("mode"),
        "would_block": d.get("would_block"),
        "flagged": bool(d.get("flagged")),
        "route_reason": d.get("route_reason"),
        "data_class_detected": d.get("data_class_detected"),
        "findings": findings,
        "masked": {k: v for k, v in masked.items() if _num(v)},
        "normalisation": d.get("normalisation") if isinstance(d.get("normalisation"), dict) else None,
        "semantic_source": semantic.get("source"),
        "semantic_score": _num(semantic.get("score")),
        "semantic_action": semantic.get("action"),
        "semantic_reason": semantic.get("reason"),
        "jev_status": jev.get("status"),
        "jev_latency_ms": _num(jev.get("latency_ms")),
        "jev_score": _num(jev.get("attack")),
        "judge_status": judge.get("status") if judge else None,
        "judge_score": _num(judge.get("score")) if judge else None,
        "judge_category": judge.get("category") if judge else None,
        "judge_latency_ms": _num(judge.get("latency_ms")) if judge else None,
        "loop": d.get("loop"),
        "budget": d.get("budget"),
        "break_glass_id": bg.get("id") if bg else None,
        "break_glass_relaxed": bg.get("relaxed") if bg else None,
        "status": u.get("status"),
        "error": error if isinstance(error, str) else None,
        "input_tokens": _num(u.get("input_tokens")) or 0,
        "output_tokens": _num(u.get("output_tokens")) or 0,
        "cost_usd": cost,
        "cost_source": cost_source,
        "shadow": bool(u.get("shadow")),
        "price_known": u.get("price_known") if u.get("price_known") is not None else cost is not None,
        "fallback_used": bool(u.get("fallback_used")),
        "guard_ms": _num(d.get("guard_ms")),
        "total_ms": _num(u.get("total_ms")),
        "policy_version": d.get("policy_version"),
        "has_usage": bool(usages),
    }


def build_dataset(rows: Iterable[dict]) -> dict:
    groups: dict = {}
    order: list = []
    tools, bg_events, incidents, shadows = [], [], [], []
    for i, row in enumerate(rows):
        t = row.get("type")
        if t == "shadow":
            shadows.append(row)
            continue
        if t == "incident":
            incidents.append(row)
            continue
        if t == "tool":
            tools.append(row)
            continue
        if t == "break_glass":
            bg_events.append(row)
            continue
        if t not in ("decision", "usage"):
            continue
        rid = row.get("request_id")
        key = rid if isinstance(rid, str) and rid else f"#row{i}"
        if key not in groups:
            groups[key] = []
            order.append((key, rid if key == rid else None))
        groups[key].append(row)
    records = [build_record(rid, groups[key]) for key, rid in order]
    records.sort(key=lambda r: r["ts"] or "")
    incidents.sort(key=lambda r: r.get("ts") or "")
    shadows.sort(key=lambda r: r.get("ts") or "")
    return {
        "records": records,
        "tools": tools,
        "break_glass": bg_events,
        "incidents": incidents,
        "shadows": shadows,
    }


# ---------------------------------------------------------------- filters and periods


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
    records: list[dict], start: date, end: date, department=None, team=None, model=None, user=None
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


def _cost(r: dict) -> tuple[float, float]:
    c = r["cost_usd"] or 0.0
    return (0.0, c) if r["shadow"] else (c, 0.0)


def _round(v, n=8):
    return None if v is None else round(v, n)


def _days(start: date, end: date) -> list[str]:
    n = (end - start).days
    return [(start + timedelta(days=i)).isoformat() for i in range(n + 1)]


# ---------------------------------------------------------------- management


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
        s, sh = _cost(r)
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
                "spend": _round(v["spend"]),
                "shadow": _round(v["shadow"]),
                "total": _round(t_),
                "requests": v["requests"],
                "budget": b,
                "utilisation": _round(t_ / b, 4) if b else None,
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
                "spend": _round(v["spend"]),
                "shadow": _round(v["shadow"]),
                "total": _round(t_),
                "budget": b,
                "utilisation": _round(t_ / b, 4) if b else None,
                "default_model": meta.get("default_model"),
            }
        )
    model_rows = [
        {
            "model": k,
            "status": status_of(k),
            "requests": v["requests"],
            "spend": _round(v["spend"]),
            "shadow": _round(v["shadow"]),
            "total": _round(v["spend"] + v["shadow"]),
        }
        for k, v in by_model.items()
    ]
    # Up to today, or to the newest record when the clocks disagree (UTC vs local midnight).
    last = max([date.fromisoformat(r["day"]) for r in records if r["day"]] + [today, start])
    days = _days(start, min(end, last))
    daily_rows = [
        {
            "day": d,
            "by_department": {k: _round(v) for k, v in daily.get(d, {}).items()},
            "total": _round(sum(daily.get(d, {}).values())),
            "requests": daily_req.get(d, 0),
            "active_users": len(daily_users.get(d, ())),
        }
        for d in days
    ]
    budget_total = sum(b for b in team_budget.values() if b)
    return {
        "kpis": {
            "spend": _round(spend),
            "shadow": _round(shadow),
            "total": _round(total),
            "forecast": _round(forecast),
            "budget_total": budget_total or None,
            "requests": len(records),
            "active_users": len({r["user"] for r in records if r["user"]}),
            "active_teams": len({r["team"] for r in records if r["team"] != UNATTRIBUTED}),
            "approved_share": _round(approved_total / total, 4) if total else None,
        },
        "departments": departments,
        "teams": team_rows,
        "models_by_cost": sorted(model_rows, key=lambda m: (-(m["total"] or 0), m["model"]))[:10],
        "models_by_requests": sorted(model_rows, key=lambda m: (-m["requests"], m["model"]))[:10],
        "daily": daily_rows,
        "forecast_daily": _round(forecast / m_end.day, 6) if forecast else None,
        "top_users": [
            {"user": u, "requests": n} for u, n in sorted(users.items(), key=lambda x: (-x[1], x[0]))[:10]
        ],
    }


def _model_status(models_doc: dict):
    entries = [m for m in models_doc.get("models", []) or [] if isinstance(m, dict)]

    def status(name):
        if not name:
            return None
        for m in entries:
            if m.get("id") == name:
                return m.get("status")
        for m in entries:
            mid = str(m.get("id", ""))
            if mid.endswith("*") and name.startswith(mid[:-1]):
                return m.get("status")
        return "unlisted"

    return status


# ---------------------------------------------------------------- security


def _pack_of(f: dict) -> str:
    pack = f.get("pack")
    return pack if pack in PACKS else "custom"


def security(
    records: list[dict],
    tools: list[dict],
    bg_events: list[dict],
    overrides: list[dict],
    review: float = 0.35,
    block: float = 0.70,
) -> dict:
    k = Counter()
    by_rule = defaultdict(lambda: {"block": 0, "flag": 0, "mask": 0, "pack": None})
    heat = defaultdict(Counter)
    masked = defaultdict(Counter)
    reroutes = Counter()
    shadow_ai = defaultdict(Counter)
    hist = [0] * 10
    sources = Counter()
    jev = Counter()
    judge = Counter()
    risky = defaultdict(lambda: {"block": 0, "flag": 0, "throttle": 0, "requests": 0})
    for r in records:
        dec = r["decision"]
        if dec == "block":
            k["blocked"] += 1
        elif r["flagged"]:
            k["flagged"] += 1
        if dec == "throttle":
            k["throttled"] += 1
        if dec == "reroute" and r["route_reason"] in POLICY_REROUTES:
            k["rerouted_policy"] += 1
        if dec == "reroute":
            reroutes[r["route_reason"] or "unknown"] += 1
        if r["route_reason"] in SHADOW_AI_REASONS:
            k["unapproved_attempts"] += 1
            shadow_ai[r["team"]][r["model_requested"] or "unknown"] += 1
        for f in r["findings"]:
            rule = f.get("rule") or "unknown"
            act = f.get("action") if f.get("action") in ("block", "flag", "mask") else "flag"
            by_rule[rule][act] += 1
            by_rule[rule]["pack"] = _pack_of(f)
            heat[r["department"]][_pack_of(f)] += 1
        for typ, n in r["masked"].items():
            masked[r["department"]][typ] += n
            k["masked_items"] += n
        if r["semantic_score"] is not None:
            hist[min(9, int(r["semantic_score"] * 10))] += 1
        sources[r["semantic_source"] or "none"] += 1
        if r["jev_status"] in ("ok", "unavailable", "error"):
            jev[r["jev_status"]] += 1
        if r["judge_status"]:
            judge["ok" if r["judge_status"] == "ok" else "down"] += 1
        who = r["user"] or r["key_id"] or r["team"]
        rk = risky[(who, r["team"])]
        rk["requests"] += 1
        if dec == "block":
            rk["block"] += 1
        elif r["flagged"]:
            rk["flag"] += 1
        if dec == "throttle":
            rk["throttle"] += 1
    active = [o for o in overrides if o.get("status") == "active"]
    k["break_glass_active"] = len(active)
    tool_calls = Counter((t.get("server"), t.get("tool")) for t in tools)
    tool_blocked = Counter((t.get("server"), t.get("tool")) for t in tools if t.get("decision") != "allow")
    suspended = sorted(
        {(t.get("server"), t.get("tool")) for t in tools if t.get("description_pinned") is False}
    )
    k["blocked_requests"] = k["blocked"]
    k["blocked"] = sum(1 for r in group_blocks(records) if r["decision"] == "block")
    risky_rows = [
        {"who": w, "team": t, **v} for (w, t), v in risky.items() if v["block"] or v["flag"] or v["throttle"]
    ]
    return {
        "kpis": {
            key: k.get(key, 0)
            for key in (
                "blocked",
                "blocked_requests",
                "flagged",
                "masked_items",
                "rerouted_policy",
                "throttled",
                "unapproved_attempts",
                "break_glass_active",
            )
        },
        "findings_by_rule": sorted(
            ({"rule": r, **v} for r, v in by_rule.items()),
            key=lambda x: (-(x["block"] + x["flag"] + x["mask"]), x["rule"]),
        ),
        "heat": {
            "packs": list(PACKS),
            "rows": [{"department": d, **{p: c.get(p, 0) for p in PACKS}} for d, c in sorted(heat.items())],
        },
        "masked": {
            "types": list(MASK_TYPES),
            "rows": [
                {"department": d, **{t: c.get(t, 0) for t in MASK_TYPES}} for d, c in sorted(masked.items())
            ],
            "totals": {t: sum(c.get(t, 0) for c in masked.values()) for t in MASK_TYPES},
        },
        "reroutes": dict(sorted(reroutes.items())),
        "shadow_ai": [
            {"team": t, "models": dict(c), "attempts": sum(c.values())} for t, c in sorted(shadow_ai.items())
        ],
        "semantic": {
            "histogram": hist,
            "review_threshold": review,
            "block_threshold": block,
            "sources": {s: sources.get(s, 0) for s in ("jev", "judge", "none")},
            "jev_availability": _round(jev["ok"] / sum(jev.values()), 4) if jev else None,
            "judge_availability": _round(judge["ok"] / sum(judge.values()), 4) if judge else None,
        },
        "risky": sorted(
            risky_rows, key=lambda x: (-(x["block"] * 3 + x["flag"] + x["throttle"]), str(x["who"]))
        )[:10],
        "break_glass": {"active": active, "events": bg_events[-50:]},
        "tools": {
            "calls": [
                {"server": s, "tool": t, "calls": n, "blocked": tool_blocked.get((s, t), 0)}
                for (s, t), n in sorted(tool_calls.items(), key=lambda x: (-x[1], str(x[0])))
            ],
            "blocked": sum(tool_blocked.values()),
            "suspended": [{"server": s, "tool": t} for s, t in suspended],
        },
        "privacy_note": "No prompt or response text is recorded by the gateway, so none can be shown or exported.",
    }


# ---------------------------------------------------------------- operations


def _agreement_bucket(key: str, checks: list[dict], escalations: list[dict]) -> dict:
    answered = [s for s in checks if s.get("agree") is not None]
    agree = sum(1 for s in answered if s["agree"])
    ps = [s["second"]["p"] for s in answered if isinstance((s.get("second") or {}).get("p"), (int, float))]
    return {
        "bucket": key,
        "checks": len(checks),
        "answered": len(answered),
        "agree": agree,
        "agreement": _round(agree / len(answered), 4) if answered else None,
        "possible_misses": sum(1 for s in answered if s.get("possible_miss")),
        "mean_p": _round(sum(ps) / len(ps), 4) if ps else None,
        "escalations": len(escalations),
        "confirmed": sum(1 for r in escalations if r["semantic_reason"] == "judge_rejected"),
        "overruled": sum(1 for r in escalations if r["semantic_reason"] == "judge_accepted"),
    }


def second_model(records: list[dict], shadows: list[dict], settings: dict, jev_enabled: bool = True) -> dict:
    """Jev and the second model on live traffic. Two views: the second model's answer on Jev's
    rejections (confirmed or overruled) and, from the shadow check, on a sample of what Jev
    accepted (agreement, possible misses). Agreement is the drift signal; it is not accuracy."""
    alert_below = float(settings.get("alert_below", 0.9))
    min_checks = int(settings.get("min_checks", 10))
    asked = [r for r in records if r["judge_status"]]
    escalated = [r for r in asked if r["semantic_reason"] in ("judge_rejected", "judge_accepted")]
    alone = [r for r in asked if r["jev_status"] != "ok" and r["semantic_source"] == "judge"]

    def buckets(width: int) -> list[dict]:
        keys = sorted(
            {(s.get("ts") or "")[:width] for s in shadows} | {(r["ts"] or "")[:width] for r in escalated}
        )
        return [
            _agreement_bucket(
                k,
                [s for s in shadows if (s.get("ts") or "")[:width] == k],
                [r for r in escalated if (r["ts"] or "")[:width] == k],
            )
            for k in keys
            if k
        ]

    days, hours = buckets(10), buckets(13)
    alert = None
    for d in reversed(days):
        if d["answered"] >= min_checks:
            if d["agreement"] is not None and d["agreement"] < alert_below:
                alert = {
                    "day": d["bucket"],
                    "agreement": d["agreement"],
                    "threshold": alert_below,
                    "checks": d["answered"],
                }
            break
    total = _agreement_bucket("all", shadows, escalated)
    misses = [
        {
            "ts": s.get("ts"),
            "team": s.get("team"),
            "user": s.get("user"),
            "model": s.get("model"),
            "source": s.get("source"),
            "jev_score": s.get("jev_score"),
            "p": (s.get("second") or {}).get("p"),
            "categories": (s.get("second") or {}).get("categories") or [],
            "request_id": s.get("request_id"),
        }
        for s in shadows
        if s.get("possible_miss")
    ]
    down = sum(1 for r in asked if r["judge_status"] != "ok")
    model = next(
        (s["second"].get("model") for s in reversed(shadows) if (s.get("second") or {}).get("model")), None
    )
    return {
        "model": model,
        "jev_enabled": jev_enabled,
        "settings": {
            "rate": settings.get("rate"),
            "samples": settings.get("samples"),
            "alert_below": alert_below,
            "min_checks": min_checks,
        },
        "total": total,
        "days": days,
        "hours": hours[-48:],
        "alert": alert,
        "decided_alone": len(alone),
        "asked": len(asked),
        "availability": _round((len(asked) - down) / len(asked), 4) if asked else None,
        "possible_misses": misses[-20:][::-1],
    }


BURST_WINDOW_S = 5.0


def group_blocks(records: list[dict], window_s: float = BURST_WINDOW_S) -> list[dict]:
    """Collapse each burst of blocked requests from one key into one attempt. An agent such as
    Claude Code sends helper calls and a retry alongside the main turn, so one refused prompt is
    several requests. Records are oldest first; a burst's first record stands for it, with
    ``repeats`` and ``request_ids``. Timing and identity only: no text is compared."""
    out: list[dict] = []
    open_bursts: dict[tuple, tuple[dict, datetime]] = {}
    for r in records:
        if r.get("decision") != "block":
            out.append(r)
            continue
        key = (r.get("team"), r.get("key_id"), r.get("user"))
        ts = _parse_ts(r.get("ts"))
        burst = open_bursts.get(key)
        if burst and ts and (ts - burst[1]).total_seconds() <= window_s:
            head = burst[0]
            head["repeats"] += 1
            head["request_ids"].append(r.get("request_id"))
            open_bursts[key] = (head, ts)
            continue
        head = {**r, "repeats": 1, "request_ids": [r.get("request_id")]}
        out.append(head)
        if ts:
            open_bursts[key] = (head, ts)
    return out


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
            "rpm_15min": _round(len(recent) / 15, 2),
            "requests": len(records),
            "p50_total_ms": p50_total,
            "p95_total_ms": percentile(totals, 95),
            "p50_guard_ms": p50_guard,
            "p95_guard_ms": percentile(guards, 95),
            "error_rate": _round(sum(errors.values()) / len(records), 4) if records else None,
            "fallback_rate": _round(sum(1 for r in with_usage if r["fallback_used"]) / len(with_usage), 4)
            if with_usage
            else None,
            "jev_availability": _round(jev["ok"] / sum(jev.values()), 4) if jev else None,
            "judge_availability": _round(judge["ok"] / sum(judge.values()), 4) if judge else None,
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


# ---------------------------------------------------------------- helpers for other pages


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


def last_used_by_key(path: str) -> dict:
    out = {}
    for r in dataset(path)["records"]:
        if r["key_id"] and r["ts"]:
            out[r["key_id"]] = max(out.get(r["key_id"], ""), r["ts"])
    return out


def filter_options(records: list[dict]) -> dict:
    return {
        "departments": sorted({r["department"] for r in records}),
        "teams": sorted({r["team"] for r in records}),
        "models": sorted({m for r in records for m in (r["model_routed"], r["model_requested"]) if m}),
        "users": sorted({r["user"] for r in records if r["user"]}),
    }


def export_row(r: dict) -> dict:
    """The exported fields only: decision and usage fields, identity, findings, masked counts."""
    return {k: r.get(k) for k in EXPORT_FIELDS}


def export_csv_value(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"), sort_keys=True)
    return str(v)


# ---------------------------------------------------------------- semantic outage

OUTAGE_MODES = ("degrade", "fail_closed")


def _parse_ts(ts) -> datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if dt else None


def manual_switch_state(switch: dict | None, now: datetime | None = None) -> dict | None:
    """The manual switch from state/break_glass.json with its effective status, or None."""
    if not isinstance(switch, dict):
        return None
    now = now or datetime.now(UTC)
    exp = _parse_ts(switch.get("expires_at"))
    status = "ended" if not switch.get("active") else ("expired" if exp and exp <= now else "active")
    return {**switch, "status": status}


def outages(
    incidents: list[dict], records: list[dict], switch: dict | None = None, now: datetime | None = None
) -> dict:
    """Circuit state per provider, outage periods (automatic and manual), and what happened meanwhile.

    Circuit state comes from the latest open/close (or half_open) event per component. Automatic
    outage periods run from outage_start to outage_end; manual ones from manual_on to manual_off
    or their expiry. The manual switch file adds a period when no manual_on row covers it.
    """
    now = now or datetime.now(UTC)
    circuits = {c: {"state": "closed", "since": None, "reason": None} for c in ("jev", "judge")}
    periods: list[dict] = []
    auto_open = manual_open = None
    for row in incidents:
        ev, comp, ts = row.get("event"), row.get("component"), row.get("ts")
        if comp in circuits and ev in ("open", "close", "half_open"):
            circuits[comp] = {
                "state": {"open": "open", "close": "closed", "half_open": "half_open"}[ev],
                "since": ts,
                "reason": row.get("reason"),
            }
        elif ev == "outage_start" and row.get("reason") == "manual switch":
            # The gateway also writes outage_start/outage_end while it enforces a manual switch.
            # Those periods are shown from manual_on rows and the switch file, not as automatic ones.
            auto_open = None
        elif ev == "outage_start":
            auto_open = {
                "kind": "automatic",
                "start": ts,
                "end": None,
                "mode": row.get("mode"),
                "reason": row.get("reason"),
                "by": row.get("by"),
                "ticket": None,
            }
        elif ev == "outage_end" and auto_open:
            auto_open["end"] = ts
            periods.append(auto_open)
            auto_open = None
        elif ev == "manual_on":
            if manual_open:
                manual_open["end"] = ts
                periods.append(manual_open)
            manual_open = {
                "kind": "manual",
                "start": ts,
                "end": None,
                "mode": row.get("mode"),
                "reason": row.get("reason"),
                "by": row.get("by"),
                "ticket": row.get("ticket"),
                "expires_at": row.get("expires_at"),
            }
        elif ev == "manual_off" and manual_open:
            manual_open["end"] = ts
            periods.append(manual_open)
            manual_open = None
    if manual_open:
        exp = _parse_ts(manual_open.get("expires_at"))
        if exp and exp <= now:
            manual_open["end"] = _iso(exp)
        periods.append(manual_open)
    if auto_open:
        periods.append(auto_open)
    sw = manual_switch_state(switch, now)
    if (
        sw
        and sw.get("mode") in OUTAGE_MODES
        and not any(
            p["kind"] == "manual"
            and p["start"]
            and sw.get("issued_at")
            and p["start"][:16] == sw["issued_at"][:16]
            for p in periods
        )
    ):
        end = (
            None
            if sw["status"] == "active"
            else (sw.get("expires_at") if sw["status"] == "expired" else None)
        )
        periods.append(
            {
                "kind": "manual",
                "start": sw.get("issued_at"),
                "end": end if sw["status"] != "ended" else sw.get("issued_at"),
                "mode": sw.get("mode"),
                "reason": sw.get("reason"),
                "by": sw.get("issued_by"),
                "ticket": sw.get("ticket"),
                "expires_at": sw.get("expires_at"),
            }
        )
    periods.sort(key=lambda p: p["start"] or "")
    for p in periods:
        a, b = _parse_ts(p["start"]), _parse_ts(p["end"]) or now
        p["duration_s"] = max(0, round((b - a).total_seconds())) if a else None
        p["ongoing"] = p["end"] is None
    windows = [(p["start"] or "", p["end"] or "9999") for p in periods if p.get("mode") != "normal"]
    inside = [r for r in records if r["ts"] and any(a <= r["ts"] <= b for a, b in windows)]
    automatic_active = any(p["ongoing"] and p["kind"] == "automatic" for p in periods)
    if sw is not None:
        manual_active = sw["status"] == "active" and sw.get("mode") in OUTAGE_MODES
    else:  # no switch file to consult: trust the audit rows
        manual_active = any(
            p["ongoing"] and p["kind"] == "manual" and p.get("mode") in OUTAGE_MODES for p in periods
        )
    active = automatic_active or manual_active
    since = None
    if active:
        starts = [p["start"] for p in periods if p["ongoing"] and p.get("mode") != "normal"]
        since = min(starts) if starts else (sw or {}).get("issued_at")
    mode = next(
        (p["mode"] for p in reversed(periods) if p["ongoing"] and p.get("mode") in OUTAGE_MODES), None
    )
    if manual_active and sw:
        mode = sw.get("mode")
    return {
        "circuits": circuits,
        "active": active,
        "automatic_active": automatic_active,
        "manual": sw,
        "since": since,
        "mode": mode,
        "periods": periods,
        "requests_outage_reason": sum(1 for r in records if r["semantic_reason"] == "outage"),
        "requests_during": len(inside),
        "blocked_during": sum(1 for r in inside if r["decision"] == "block"),
        "flagged_during": sum(1 for r in inside if r["flagged"] and r["decision"] != "block"),
    }
