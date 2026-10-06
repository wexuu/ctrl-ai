"""Admin API: session, config read/validate/save/rollback, history, keys, break-glass, admin log.

Every route depends on ctrl_ai.admin.auth.current_admin (open access: local-admin; production: the SSO identity),
and every state-changing route needs the X-CTRL-AI-CSRF header. Contents of config files are never logged.
"""

from __future__ import annotations

import difflib
import re
import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ctrl_ai.admin import admin_audit, analytics, auth, config_store, keys, mcp_admin, regex_guard
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()
TEST_SAMPLE_MAX = 20_000


def _error(exc: StoreError) -> JSONResponse:
    return JSONResponse(exc.to_dict(), status_code=exc.status)


# ---------------------------------------------------------------- session (no sign-in)


@router.get("/api/auth/session")
def session(admin: auth.Admin = Depends(auth.current_admin)):
    """Who the panel acts as, and the CSRF token for changes. Production: the SSO identity."""
    return {
        "user": admin.name,
        "roles": admin.roles,
        "csrf": auth.csrf_token(),
        "open_access": True,
        "banner": auth.ACCESS_BANNER,
    }


@router.get("/api/nav")
def nav(request: Request, settings: AdminSettings = Depends(admin_settings)):
    """What the top bar shows: policy mode and version; break-glass count for admins."""
    out: dict[str, Any] = {
        "policy_mode": None,
        "policy_version": None,
        "break_glass_active": None,
        "user": None,
    }
    try:
        doc, _, version = config_store.read(settings, "policy")
        out["policy_mode"], out["policy_version"] = doc.get("mode"), version
    except StoreError:
        pass
    out["user"] = auth.resolve_admin(request).name
    out["break_glass_active"] = len(keys.active_overrides(settings))
    out["outage"] = _outage_summary(settings)
    return out


def _outage_summary(settings: AdminSettings) -> dict:
    """What the outage banner needs: active, since, mode, and the manual switch's who/ticket/expiry."""
    try:
        data = analytics.dataset(settings.audit_log)
        o = analytics.outages(data["incidents"], data["records"], keys.outage_switch(settings))
    except Exception:
        return {"active": False}
    manual = o.get("manual") if o.get("manual") and o["manual"].get("status") == "active" else None
    if manual is None:
        manual = next((p for p in reversed(o["periods"]) if p["kind"] == "manual" and p["ongoing"]), None)
    return {
        "active": o["active"],
        "since": o["since"],
        "mode": o["mode"],
        "circuits": {k: v["state"] for k, v in o["circuits"].items()},
        "manual": {
            "by": manual.get("issued_by") or manual.get("by"),
            "ticket": manual.get("ticket"),
            "expires_at": manual.get("expires_at"),
            "mode": manual.get("mode"),
        }
        if manual
        else None,
    }


# ---------------------------------------------------------------- config files


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
        return _error(exc)
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
        return _error(exc)
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
        return _error(exc)
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
        return _error(exc)
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
        return _error(exc)


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
        return _error(exc)
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
    return {"packs": config_store.PACK_RULES, "labels": config_store.PACK_LABELS}


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


# ---------------------------------------------------------------- keys and break-glass


class IssueBody(BaseModel):
    team: str
    user: str
    label: str = ""
    expires: str | None = None


class ReasonBody(BaseModel):
    reason: str = ""


def _last_used(settings: AdminSettings) -> dict:
    try:
        return analytics.last_used_by_key(settings.audit_log)
    except Exception:
        return {}


@router.get("/api/admin/keys")
def list_keys(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    return {"keys": keys.list_keys(settings, _last_used(settings))}


@router.post("/api/admin/keys")
def issue_key(
    body: IssueBody,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        key, record = keys.issue(settings, body.team, body.user, body.label, body.expires, actor=admin.name)
    except StoreError as exc:
        return _error(exc)
    public = {k: record[k] for k in ("id", "prefix", "team", "user", "label", "created", "expires")}
    return {"key": key, "record": public, "note": "This key is shown once and cannot be shown again."}


@router.post("/api/admin/keys/{key_id}/revoke")
def revoke_key(
    key_id: str,
    body: ReasonBody,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        record = keys.revoke(settings, key_id, actor=admin.name, reason=body.reason)
    except StoreError as exc:
        return _error(exc)
    return {"id": record["id"], "revoked": True}


@router.get("/api/admin/break-glass")
def list_break_glass(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    return {"overrides": keys.list_overrides(settings), "now": time.time()}


@router.post("/api/admin/break-glass/{override_id}/revoke")
def revoke_break_glass(
    override_id: str,
    body: ReasonBody,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        record = keys.revoke_override(settings, override_id, actor=admin.name, reason=body.reason)
    except StoreError as exc:
        return _error(exc)
    return {"id": record["id"], "revoked": True}


# ---------------------------------------------------------------- admin audit log


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


# ---------------------------------------------------------------- MCP tool servers


class RepinBody(BaseModel):
    server: str
    tool: str
    reason: str = ""


@router.get("/api/admin/mcp")
def mcp_servers(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    doc, _, version = config_store.read(settings, "mcp")
    return {"version": version, "servers": [mcp_admin.server_view(s) for s in doc.get("servers", []) or []]}


@router.post("/api/admin/mcp/repin")
def mcp_repin(
    body: RepinBody,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    if len(body.reason.strip()) < 3:
        return JSONResponse({"error": "A reason of at least 3 characters is required"}, status_code=422)
    try:
        version = mcp_admin.repin(settings, body.server, body.tool, actor=admin.name, reason=body.reason)
    except StoreError as exc:
        return _error(exc)
    except httpx.HTTPError as exc:
        return JSONResponse({"error": f"cannot reach the server ({type(exc).__name__})"}, status_code=502)
    return {"version": version}


# ---------------------------------------------------------------- semantic-outage switch


class OutageBody(BaseModel):
    mode: str
    minutes: int = 30
    reason: str = ""
    ticket: str = ""


def _max_outage_minutes(settings: AdminSettings) -> int:
    so = config_store.read_doc(settings, "policy").get("semantic_outage") or {}
    return int(so.get("max_manual_minutes") or keys.DEFAULT_MAX_OUTAGE_MINUTES)


@router.get("/api/admin/semantic-outage")
def semantic_outage(
    admin: auth.Admin = Depends(auth.current_admin), settings: AdminSettings = Depends(admin_settings)
):
    data = analytics.dataset(settings.audit_log)
    o = analytics.outages(data["incidents"], data["records"], keys.outage_switch(settings))
    policy = config_store.read_doc(settings, "policy").get("semantic_outage") or {}
    return {
        "switch": o["manual"],
        "circuits": o["circuits"],
        "active": o["active"],
        "mode": o["mode"],
        "since": o["since"],
        "periods": o["periods"][-10:],
        "policy": policy,
        "max_minutes": _max_outage_minutes(settings),
    }


@router.post("/api/admin/semantic-outage")
def set_semantic_outage(
    body: OutageBody,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        record = keys.set_outage(
            settings,
            body.mode,
            body.minutes,
            body.reason,
            body.ticket,
            actor=admin.name,
            max_minutes=_max_outage_minutes(settings),
        )
    except StoreError as exc:
        return _error(exc)
    return {"switch": record}


@router.post("/api/admin/semantic-outage/end")
def end_semantic_outage(
    body: ReasonBody,
    admin: auth.Admin = Depends(auth.current_admin),
    settings: AdminSettings = Depends(admin_settings),
):
    try:
        record = keys.end_outage(settings, actor=admin.name, reason=body.reason)
    except StoreError as exc:
        return _error(exc)
    return {"switch": record}
