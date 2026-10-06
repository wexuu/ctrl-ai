"""Dashboard API: aggregates of the audit log for the Management, Security and Operations views,
the request list, the auditor export, and small helpers used by the admin pages.

All figures come from ctrl_ai.admin.analytics (pure). No prompt or response text exists in the audit log,
so none can be returned or exported.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse

from ctrl_ai.admin import admin_audit, analytics, auth, config_store, keys
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()


def _context(settings: AdminSettings, frm, to, department, team, model, user):
    data = analytics.dataset(settings.audit_log)
    start, end = analytics.parse_period(frm, to)
    records = analytics.apply_filters(
        data["records"], start, end, department or None, team or None, model or None, user or None
    )
    return data, start, end, records


def _period(start, end, **filters) -> dict:
    return {
        "from": start.isoformat(),
        "to": end.isoformat(),
        "filters": {k: v for k, v in filters.items() if v},
    }


@router.get("/api/dash/filters")
def dash_filters(
    frm: str | None = Query(None, alias="from"),
    to: str | None = None,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    data = analytics.dataset(settings.audit_log)
    start, end = analytics.parse_period(frm, to)
    opts = analytics.filter_options(analytics.apply_filters(data["records"], start, end))
    teams_doc = config_store.read_doc(settings, "teams")
    opts["departments"] = sorted(
        set(opts["departments"]) | {d["id"] for d in teams_doc.get("departments", [])}
    )
    opts["teams"] = sorted(set(opts["teams"]) | {t["id"] for t in teams_doc.get("teams", [])})
    opts["period"] = {"from": start.isoformat(), "to": end.isoformat()}
    opts["rows_total"] = len(data["records"])
    return opts


@router.get("/api/dash/management")
def dash_management(
    frm: str | None = Query(None, alias="from"),
    to: str | None = None,
    department: str | None = None,
    team: str | None = None,
    model: str | None = None,
    user: str | None = None,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    _data, start, end, records = _context(settings, frm, to, department, team, model, user)
    teams_doc = config_store.read_doc(settings, "teams")
    if department or team:
        teams_doc = dict(
            teams_doc,
            teams=[
                t
                for t in teams_doc.get("teams", [])
                if (not team or t.get("id") == team) and (not department or t.get("department") == department)
            ],
        )
        teams_doc["departments"] = [
            d for d in teams_doc.get("departments", []) if not department or d.get("id") == department
        ]
    out = analytics.management(records, start, end, teams_doc, config_store.read_doc(settings, "models"))
    out["period"] = _period(start, end, department=department, team=team, model=model, user=user)
    return out


def _thresholds(settings: AdminSettings) -> tuple[float, float]:
    jev = config_store.read_doc(settings, "policy").get("jev") or {}
    return float(jev.get("review_threshold", 0.35)), float(jev.get("block_threshold", 0.70))


@router.get("/api/dash/security")
def dash_security(
    frm: str | None = Query(None, alias="from"),
    to: str | None = None,
    department: str | None = None,
    team: str | None = None,
    model: str | None = None,
    user: str | None = None,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    data, start, end, records = _context(settings, frm, to, department, team, model, user)
    lo, hi = start.isoformat(), end.isoformat()
    tools = [
        t
        for t in data["tools"]
        if lo <= (t.get("ts") or "")[:10] <= hi and (not team or t.get("team") == team)
    ]
    bg = [b for b in data["break_glass"] if lo <= (b.get("ts") or "")[:10] <= hi]
    review, block = _thresholds(settings)
    out = analytics.security(records, tools, bg, keys.list_overrides(settings), review, block)
    out["period"] = _period(start, end, department=department, team=team, model=model, user=user)
    return out


def _prometheus(base: str) -> dict | None:
    """Per-span p95 from Prometheus (OpenTelemetry span metrics), when configured and reachable."""
    if not base:
        return None
    query = (
        "histogram_quantile(0.95, sum by (le, span_name) "
        "(rate(traces_span_metrics_duration_milliseconds_bucket[15m])))"
    )
    try:
        resp = httpx.get(base + "/api/v1/query", params={"query": query}, timeout=2.0)
        result = resp.json().get("data", {}).get("result", [])
        rows = []
        for item in result:
            try:
                val = float(item["value"][1])
            except (KeyError, ValueError, TypeError):
                continue
            if val == val:  # not NaN
                rows.append({"span": item.get("metric", {}).get("span_name"), "p95_ms": round(val, 1)})
        return {"available": True, "p95_by_span": sorted(rows, key=lambda r: -r["p95_ms"])[:12]}
    except (httpx.HTTPError, ValueError):
        return {"available": False, "p95_by_span": []}


@router.get("/api/dash/operations")
def dash_operations(
    frm: str | None = Query(None, alias="from"),
    to: str | None = None,
    department: str | None = None,
    team: str | None = None,
    model: str | None = None,
    user: str | None = None,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    data, start, end, records = _context(settings, frm, to, department, team, model, user)
    out = analytics.operations(records, prometheus=_prometheus(settings.prometheus_url))
    out["outage"] = analytics.outages(data["incidents"], records, keys.outage_switch(settings))
    lo, hi = start.isoformat(), end.isoformat()
    # Periods overlapping the selected dates (an outage that started before the period still shows).
    out["outage"]["periods"] = [
        p
        for p in out["outage"]["periods"]
        if (p["start"] or "")[:10] <= hi and ((p["end"] or "9999")[:10] >= lo)
    ]
    out["period"] = _period(start, end, department=department, team=team, model=model, user=user)
    return out


@router.get("/api/dash/requests")
def dash_requests(
    frm: str | None = Query(None, alias="from"),
    to: str | None = None,
    department: str | None = None,
    team: str | None = None,
    model: str | None = None,
    user: str | None = None,
    decision: str | None = None,
    rule: str | None = None,
    page: int = 1,
    size: int = 50,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    _data, _start, _end, records = _context(settings, frm, to, department, team, model, user)
    records = analytics.group_blocks(records)
    if decision:
        records = [r for r in records if r["decision"] == decision or (decision == "flag" and r["flagged"])]
    if rule:
        records = [
            r for r in records if r["rule"] == rule or any(f.get("rule") == rule for f in r["findings"])
        ]
    records = list(reversed(records))
    size = max(1, min(size, 200))
    page = max(1, page)
    chunk = records[(page - 1) * size : page * size]
    return {
        "total": len(records),
        "page": page,
        "size": size,
        "records": [
            {**analytics.export_row(r), "repeats": r.get("repeats", 1), "request_ids": r.get("request_ids")}
            for r in chunk
        ],
    }


@router.get("/api/dash/export")
def dash_export(
    format: str = "csv",
    frm: str | None = Query(None, alias="from"),
    to: str | None = None,
    department: str | None = None,
    team: str | None = None,
    model: str | None = None,
    user: str | None = None,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    """The filtered records for an auditor: identity, decision, findings, masked counts, usage. Never text."""
    _data, start, end, records = _context(settings, frm, to, department, team, model, user)
    rows = [analytics.export_row(r) for r in records]
    filters = {k: v for k, v in dict(department=department, team=team, model=model, user=user).items() if v}
    versions = sorted({r["policy_version"] for r in records if r["policy_version"]})
    generated = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = {
        "report": "ctrl-ai audit export",
        "period": {"from": start.isoformat(), "to": end.isoformat()},
        "filters": filters,
        "generated_at": generated,
        "generated_by": admin.name,
        "rows": len(rows),
        "policy_versions": versions,
        "note": "No prompt or response text is recorded by the gateway; this export contains none.",
    }
    admin_audit.write(
        settings.admin_audit_log,
        "export",
        actor=admin.name,
        target=f"{format}:{start.isoformat()}..{end.isoformat()}",
        extra={"rows": len(rows), **filters},
    )
    ext = "json" if format == "json" else "csv"
    disposition = {"content-disposition": f'attachment; filename="ctrl-ai-audit-{start}-{end}.{ext}"'}
    if format == "json":
        return JSONResponse({"header": header, "records": rows}, headers=disposition)
    buf = io.StringIO()
    buf.write("# " + json.dumps(header, separators=(",", ":")) + "\n")
    writer = csv.writer(buf)
    writer.writerow(analytics.EXPORT_FIELDS)
    for r in rows:
        writer.writerow([analytics.export_csv_value(r[k]) for k in analytics.EXPORT_FIELDS])
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv; charset=utf-8", headers=disposition
    )


@router.get("/api/dash/model-usage")
def dash_model_usage(
    days: int = 7,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    today = datetime.now(UTC).date()
    since = (today - timedelta(days=max(1, min(days, 366)) - 1)).isoformat()
    return {
        "since": since,
        "models": analytics.model_usage(analytics.dataset(settings.audit_log)["records"], since),
    }


@router.get("/api/dash/team-spend")
def dash_team_spend(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    return analytics.team_spend(
        analytics.dataset(settings.audit_log)["records"], config_store.read_doc(settings, "teams")
    )
