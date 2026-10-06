"""The manual semantic-outage switch."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ctrl_ai.admin import auth, config_store, keys
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.dashboard.semantic import outages
from ctrl_ai.admin.records import dataset
from ctrl_ai.admin.routes.common import ReasonBody, error_response
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()


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
    data = dataset(settings.audit_log)
    o = outages(data["incidents"], data["records"], keys.outage_switch(settings))
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
        return error_response(exc)
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
        return error_response(exc)
    return {"switch": record}
