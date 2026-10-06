"""Gateway keys and break-glass overrides."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ctrl_ai.admin import auth, keys
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.records import last_used_by_key
from ctrl_ai.admin.routes.common import ReasonBody, error_response
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()


class IssueBody(BaseModel):
    team: str
    user: str
    label: str = ""
    expires: str | None = None


def _last_used(settings: AdminSettings) -> dict:
    try:
        return last_used_by_key(settings.audit_log)
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
        return error_response(exc)
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
        return error_response(exc)
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
        return error_response(exc)
    return {"id": record["id"], "revoked": True}
