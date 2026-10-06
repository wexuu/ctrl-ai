"""MCP tool servers: the live tool list with pin status, and re-pinning a reviewed tool."""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ctrl_ai.admin import auth, config_store, mcp_admin
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.routes.common import error_response
from ctrl_ai.admin.settings import AdminSettings, admin_settings

router = APIRouter()


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
        return error_response(exc)
    except (httpx.HTTPError, RuntimeError, ValueError) as exc:
        return JSONResponse({"error": f"cannot reach the server ({type(exc).__name__})"}, status_code=502)
    return {"version": version}
