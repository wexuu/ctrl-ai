"""The semantic checks on live traffic: the second model against Jev, and semantic outages."""

from __future__ import annotations

from datetime import UTC, datetime

from ctrl_ai.admin.dashboard.common import (
    parse_ts,
    rounded,
)


def _agreement_bucket(key: str, checks: list[dict], escalations: list[dict]) -> dict:
    answered = [s for s in checks if s.get("agree") is not None]
    agree = sum(1 for s in answered if s["agree"])
    ps = [s["second"]["p"] for s in answered if isinstance((s.get("second") or {}).get("p"), (int, float))]
    return {
        "bucket": key,
        "checks": len(checks),
        "answered": len(answered),
        "agree": agree,
        "agreement": rounded(agree / len(answered), 4) if answered else None,
        "possible_misses": sum(1 for s in answered if s.get("possible_miss")),
        "mean_p": rounded(sum(ps) / len(ps), 4) if ps else None,
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
        "availability": rounded((len(asked) - down) / len(asked), 4) if asked else None,
        "possible_misses": misses[-20:][::-1],
    }


OUTAGE_MODES = ("degrade", "fail_closed")


def _iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if dt else None


def manual_switch_state(switch: dict | None, now: datetime | None = None) -> dict | None:
    """The manual switch from state/break_glass.json with its effective status, or None."""
    if not isinstance(switch, dict):
        return None
    now = now or datetime.now(UTC)
    exp = parse_ts(switch.get("expires_at"))
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
        exp = parse_ts(manual_open.get("expires_at"))
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
        a, b = parse_ts(p["start"]), parse_ts(p["end"]) or now
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
