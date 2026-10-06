"""The security view: blocks, findings, masking, reroutes, semantic scores, tools and break-glass."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from ctrl_ai.admin.dashboard.common import (
    POLICY_REROUTES,
    SHADOW_AI_REASONS,
    parse_ts,
    rounded,
)
from ctrl_ai.detect.packs import PACK_IDS

MASK_TYPES = ("iban", "pesel", "nip", "card", "email", "phone")
PACKS = (*PACK_IDS, "custom")


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
            "jev_availability": rounded(jev["ok"] / sum(jev.values()), 4) if jev else None,
            "judge_availability": rounded(judge["ok"] / sum(judge.values()), 4) if judge else None,
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
        ts = parse_ts(r.get("ts"))
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
