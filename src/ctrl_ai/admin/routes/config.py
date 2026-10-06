"""The configuration files: read, validate, save, history, diff, rollback; the rule tester,
the signature feed, the packs, the gateway's model list and the admin audit log."""

from __future__ import annotations

import difflib
import re

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ctrl_ai.admin import admin_audit, auth, config_store, regex_guard
from ctrl_ai.admin.config_checks import PACK_LABELS, PACK_RULES
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.routes.common import error_response
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()


TEST_SAMPLE_MAX = 20_000


class SaveBody(BaseModel):
    doc: dict
    expected_version: str | None = None
    reason: str = ""


class ValidateBody(BaseModel):
    doc: dict


class RollbackBody(BaseModel):
    version: str
    reason: str = ""


@router.get("/api/admin/config/{name}")
def get_config(
    name: str,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        doc, text, version = config_store.read(settings, name)
    except StoreError as exc:
        return error_response(exc)
    return {
        "name": name,
        "doc": doc,
        "text": text,
        "version": version,
        "file": config_store.path_of(settings, name).name,
    }


@router.post("/api/admin/config/{name}/validate")
def validate_config(
    name: str,
    body: ValidateBody,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        errors = config_store.validate(settings, name, body.doc)
        preview = config_store.render(settings, name, body.doc) if not errors else None
    except StoreError as exc:
        return error_response(exc)
    _, current_text, _ = config_store.read(settings, name)
    diff = None
    if preview is not None:
        diff = "".join(
            difflib.unified_diff(
                current_text.splitlines(True),
                preview.splitlines(True),
                fromfile=f"{name} (current)",
                tofile=f"{name} (new)",
            )
        )
    return {"errors": [e.to_dict() for e in errors], "diff": diff}


@router.post("/api/admin/config/{name}")
def save_config(
    name: str,
    body: SaveBody,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        version = config_store.save(
            settings,
            name,
            body.doc,
            expected_version=body.expected_version,
            actor=admin.name,
            reason=body.reason,
        )
    except StoreError as exc:
        return error_response(exc)
    return {"version": version}


@router.get("/api/admin/config/{name}/history")
def config_history(
    name: str,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        entries = config_store.history(settings, name)
        _, _, current = config_store.read(settings, name)
    except StoreError as exc:
        return error_response(exc)
    rows = [
        r
        for r in admin_audit.read(settings.admin_audit_log)
        if str(r.get("action", "")).startswith(name + ".")
    ]
    by_after = {}
    for r in reversed(rows):  # oldest first, so the newest row for a version wins
        if r.get("version_after"):
            by_after[r["version_after"]] = r

    def who(version):
        r = by_after.get(version) or {}
        return {
            "actor": r.get("actor"),
            "reason": r.get("reason"),
            "action": r.get("action"),
            "saved_at": r.get("ts"),
        }

    return {
        "current": {"version": current, **who(current)},
        "versions": [{**e, **who(e["version"])} for e in entries],
    }


@router.get("/api/admin/config/{name}/diff")
def config_diff(
    name: str,
    version: str,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        return {"diff": config_store.diff(settings, name, version)}
    except StoreError as exc:
        return error_response(exc)


@router.post("/api/admin/config/{name}/rollback")
def config_rollback(
    name: str,
    body: RollbackBody,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        version = config_store.rollback(settings, name, body.version, actor=admin.name, reason=body.reason)
    except StoreError as exc:
        return error_response(exc)
    return {"version": version}


@router.get("/api/admin/signatures")
def signatures(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    doc = config_store.signatures_doc(settings)
    return {
        "feed_version": doc.get("feed_version"),
        "signatures": [
            {k: s.get(k) for k in ("id", "category", "source", "applies_to", "action", "guidance")}
            for s in doc.get("signatures", []) or []
            if isinstance(s, dict)
        ],
    }


@router.get("/api/admin/packs")
def packs(admin: auth.Admin = Depends(auth.current_admin)):
    return {"packs": PACK_RULES, "labels": PACK_LABELS}


# ---------------------------------------------------------------- rule tester


class TestRuleBody(BaseModel):
    type: str
    value: str
    sample: str


@router.post("/api/admin/policy/test-rule")
def test_rule(body: TestRuleBody, admin: auth.Admin = Depends(auth.current_admin)):
    """Does a rule match a sample? The sample is never stored or logged."""
    sample = body.sample[:TEST_SAMPLE_MAX]
    if not body.value:
        return JSONResponse({"error": "value is empty"}, status_code=422)
    if body.type == "contains":
        spans, start = [], 0
        while len(spans) < 50:
            i = sample.find(body.value, start)
            if i < 0:
                break
            spans.append([i, i + len(body.value)])
            start = i + max(1, len(body.value))
        return {"matched": bool(spans), "spans": spans}
    if body.type != "regex":
        return JSONResponse({"error": "type must be contains or regex"}, status_code=422)
    problem = regex_guard.check(body.value)
    if problem:
        return JSONResponse({"error": f"Refused: the regex {problem}", "refused": True}, status_code=422)
    spans = [[m.start(), m.end()] for _, m in zip(range(50), re.finditer(body.value, sample), strict=False)]
    return {"matched": bool(spans), "spans": spans}


# ---------------------------------------------------------------- gateway models


@router.get("/api/admin/gateway-models")
async def gateway_models(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    url = settings.gateway_url + "/v1/models"
    headers = {"authorization": "Bearer " + settings.master_key}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0)) as client:
            resp = await client.get(url, headers=headers)
        ids = (
            sorted({m.get("id") for m in resp.json().get("data", []) if m.get("id")})
            if resp.status_code == 200
            else []
        )
        return {"models": ids, "error": None if resp.status_code == 200 else f"HTTP {resp.status_code}"}
    except (httpx.HTTPError, ValueError) as exc:
        return {"models": [], "error": f"gateway unreachable ({type(exc).__name__})"}


@router.get("/api/admin/audit")
def admin_log(
    action: str | None = None,
    actor: str | None = None,
    limit: int = 500,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    rows = admin_audit.read(settings.admin_audit_log, limit=max(1, min(limit, 5000)))
    if action:
        rows = [r for r in rows if r.get("action") == action]
    if actor:
        rows = [r for r in rows if r.get("actor") == actor]
    return {"rows": rows}
