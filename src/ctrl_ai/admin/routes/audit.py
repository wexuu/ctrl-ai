"""The home page redirect, the health check, and the audit page's and policy summary's data."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, RedirectResponse

from ctrl_ai.admin.records import audit_entries
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()


@router.get("/")
def index() -> RedirectResponse:
    # The dashboard is the home page.
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/api/audit")
def audit(
    limit: int = Query(200, ge=1, le=5000),
    request_id: str | None = None,
    settings: AdminSettings = Depends(admin_settings),
) -> dict:
    """The newest audit records, decision and usage rows joined by request_id."""
    return {"records": audit_entries(settings.audit_log, limit, request_id)}


@router.get("/api/policy")
def policy(settings: AdminSettings = Depends(admin_settings)) -> JSONResponse:
    """Mode, rules, Jev switch and version of the policy file, as the guardrail would see it."""
    try:
        raw = Path(settings.policy_file).read_bytes()
    except OSError as exc:
        return JSONResponse({"error": f"policy file not readable ({type(exc).__name__})"})
    out: dict = {
        "version": hashlib.sha256(raw).hexdigest()[:8],
        "mode": None,
        "rules": [],
        "jev_enabled": None,
        "error": None,
    }
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError:
        doc = None
    if not isinstance(doc, dict):
        out["error"] = "not a valid policy file; the gateway keeps its last valid version"
        return JSONResponse(out)
    out["mode"] = doc.get("mode")
    rules = doc.get("rules")
    rules = rules if isinstance(rules, list) else []
    out["rules"] = [{"id": r.get("id"), "type": r.get("type")} for r in rules if isinstance(r, dict)]
    jev = doc.get("jev")
    jev = jev if isinstance(jev, dict) else {}
    out["jev_enabled"] = jev.get("enabled", True)
    return JSONResponse(out)
