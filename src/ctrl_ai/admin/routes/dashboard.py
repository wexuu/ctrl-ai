"""Dashboard API: aggregates of the audit log for the Management, Security and Operations views,
the request list, the auditor export, and small helpers used by the admin pages.

All figures come from ctrl_ai.admin.analytics (pure). No prompt or response text exists in the audit log,
so none can be returned or exported.
"""

from __future__ import annotations

import csv
import io
import json
import math
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse

from ctrl_ai.admin import admin_audit, auth, config_store, keys
from ctrl_ai.admin.dashboard.common import (
    apply_filters,
    filter_options,
    model_usage,
    parse_period,
    team_spend,
)
from ctrl_ai.admin.dashboard.management import management
from ctrl_ai.admin.dashboard.operations import operations
from ctrl_ai.admin.dashboard.security import group_blocks, security
from ctrl_ai.admin.dashboard.semantic import outages
from ctrl_ai.admin.records import EXPORT_FIELDS, dataset, export_csv_value, export_row
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()


@dataclass
class View:
    """The records one dashboard request looks at: the audit dataset, the period and the filters."""

    data: dict
    start: date
    end: date
    records: list[dict]
    filters: dict[str, str]  # the department, team, model and user filters that are set

    def period(self) -> dict:
        return {"from": self.start.isoformat(), "to": self.end.isoformat(), "filters": self.filters}


def view(
    *,
    frm: str | None = Query(None, alias="from"),
    to: str | None = None,
    department: str | None = None,
    team: str | None = None,
    model: str | None = None,
    user: str | None = None,
    settings: AdminSettings = Depends(admin_settings),
) -> View:
    """FastAPI dependency: the period (from, to) and filter query parameters, applied."""
    data = dataset(settings.audit_log)
    start, end = parse_period(frm, to)
    filters = {
        k: v for k, v in {"department": department, "team": team, "model": model, "user": user}.items() if v
    }
    records = apply_filters(data["records"], start, end, **filters)
    return View(data, start, end, records, filters)


@router.get("/api/dash/filters")
def dash_filters(
    frm: str | None = Query(None, alias="from"),
    to: str | None = None,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    data = dataset(settings.audit_log)
    start, end = parse_period(frm, to)
    opts = filter_options(apply_filters(data["records"], start, end))
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
    v: View = Depends(view),
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    department, team = v.filters.get("department"), v.filters.get("team")
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
    out = management(v.records, v.start, v.end, teams_doc, config_store.read_doc(settings, "models"))
    out["period"] = v.period()
    return out


def _thresholds(settings: AdminSettings) -> tuple[float, float]:
    jev = config_store.read_doc(settings, "policy").get("jev") or {}
    return float(jev.get("review_threshold", 0.35)), float(jev.get("block_threshold", 0.70))


@router.get("/api/dash/security")
def dash_security(
    v: View = Depends(view),
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    lo, hi = v.start.isoformat(), v.end.isoformat()
    team = v.filters.get("team")
    tools = [
        t
        for t in v.data["tools"]
        if lo <= (t.get("ts") or "")[:10] <= hi and (not team or t.get("team") == team)
    ]
    bg = [b for b in v.data["break_glass"] if lo <= (b.get("ts") or "")[:10] <= hi]
    review, block = _thresholds(settings)
    out = security(v.records, tools, bg, keys.list_overrides(settings), review, block)
    out["period"] = v.period()
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
            if not math.isnan(val):
                rows.append({"span": item.get("metric", {}).get("span_name"), "p95_ms": round(val, 1)})
        return {"available": True, "p95_by_span": sorted(rows, key=lambda r: -r["p95_ms"])[:12]}
    except (httpx.HTTPError, ValueError):
        return {"available": False, "p95_by_span": []}


@router.get("/api/dash/operations")
def dash_operations(
    v: View = Depends(view),
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    out = operations(v.records, prometheus=_prometheus(settings.prometheus_url))
    out["outage"] = outages(v.data["incidents"], v.records, keys.outage_switch(settings))
    lo, hi = v.start.isoformat(), v.end.isoformat()
    # Periods overlapping the selected dates (an outage that started before the period still shows).
    out["outage"]["periods"] = [
        p
        for p in out["outage"]["periods"]
        if (p["start"] or "")[:10] <= hi and ((p["end"] or "9999")[:10] >= lo)
    ]
    out["period"] = v.period()
    return out


@router.get("/api/dash/requests")
def dash_requests(
    v: View = Depends(view),
    decision: str | None = None,
    rule: str | None = None,
    page: int = 1,
    size: int = 50,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    records = group_blocks(v.records)
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
            {**export_row(r), "repeats": r.get("repeats", 1), "request_ids": r.get("request_ids")}
            for r in chunk
        ],
    }


@router.get("/api/dash/export")
def dash_export(
    format: str = "csv",
    v: View = Depends(view),
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    """The filtered records for an auditor: identity, decision, findings, masked counts, usage. Never text."""
    start, end, filters = v.start, v.end, v.filters
    rows = [export_row(r) for r in v.records]
    versions = sorted({r["policy_version"] for r in v.records if r["policy_version"]})
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
    writer.writerow(EXPORT_FIELDS)
    for r in rows:
        writer.writerow([export_csv_value(r[k]) for k in EXPORT_FIELDS])
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
        "models": model_usage(dataset(settings.audit_log)["records"], since),
    }


@router.get("/api/dash/team-spend")
def dash_team_spend(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    return team_spend(dataset(settings.audit_log)["records"], config_store.read_doc(settings, "teams"))
