"""The session (who the panel acts as, the CSRF token) and the top bar."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from ctrl_ai.admin import auth, config_store, keys
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.dashboard.semantic import outages
from ctrl_ai.admin.records import dataset
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()


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
        data = dataset(settings.audit_log)
        o = outages(data["incidents"], data["records"], keys.outage_switch(settings))
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
