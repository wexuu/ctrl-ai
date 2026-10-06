"""Jev trust API: reads the published audit report. GET only, zero model calls.

The report is written by ``scripts/xai_audit.py`` (``make xai-audit`` / ``make xai-replay``).
Case text is returned only for the authored synthetic casebook; production prompts are never
stored, so there is nothing else to resolve.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from ctrl_ai.admin import analytics, auth, config_store
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()


def _report_path(settings: AdminSettings) -> Path:
    return Path(settings.xai_reports) / "latest.json"


def _cases_path(settings: AdminSettings) -> Path:
    return Path(settings.xai_dataset) / "cases.jsonl"


@router.get("/api/xai/report")
def xai_report(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    path = _report_path(settings)
    if not path.is_file():
        return {"state": "no_report", "hint": "Run make xai-replay (no keys) or make xai-audit."}
    try:
        report = json.loads(path.read_text())
    except (OSError, ValueError):
        return {
            "state": "unreadable",
            "hint": "The latest report could not be read; the previous version is kept.",
        }
    mtime = datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat(timespec="seconds")
    report["state"] = "ok"
    report["published_at"] = mtime
    return report


@router.get("/api/xai/case/{case_id}")
def xai_case(
    case_id: str,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    path = _cases_path(settings)
    if path.is_file() and len(case_id) <= 16:
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            case = json.loads(line)
            if case.get("case_id") == case_id and case.get("input_origin") == "authored_synthetic":
                return {
                    k: case.get(k) for k in ("case_id", "family_id", "source", "task", "text", "input_origin")
                }
    raise HTTPException(404, "not found")


@router.get("/api/xai/live")
def xai_live(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    """Jev and the second model on live traffic, from the audit log (no text, no model calls)."""
    doc = config_store.read_doc(settings, "policy")
    shadow = (doc.get("judge") or {}).get("shadow") or {}
    data = analytics.dataset(settings.audit_log)
    return analytics.second_model(
        data["records"],
        data.get("shadows", []),
        shadow,
        jev_enabled=(doc.get("jev") or {}).get("enabled", True) is not False,
    )
