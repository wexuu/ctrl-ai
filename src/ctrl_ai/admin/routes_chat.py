"""Staging chat, models, audit and policy endpoints.

Staging UI: a chat in front of the gateway and a viewer for the audit log.

The master key stays on this server: the browser never receives it. Chat text is never
logged or written anywhere; it lives in the browser and in the request in flight.
"""

from __future__ import annotations

import functools
import hashlib
from pathlib import Path
from typing import Literal

import httpx
import yaml
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from ctrl_ai.admin import audit_reader
from ctrl_ai.admin.settings import AdminSettings, admin_settings

STATIC = Path(__file__).resolve().parent / "static"
GATEWAY_TIMEOUT = httpx.Timeout(60.0, connect=5.0)
MAX_TOKENS = 4096
BLOCK_TEXT = "Blocked by ctrl-ai"
# Provider models need a key in .env. Compose passes only the names of the models whose key is
# set (CTRL_AI_UI_KEYED_MODELS), never the keys, so a model without one can be hidden from the page.
KEYED_PROVIDER_MODELS = {"chat-mistral": "MISTRAL_API_KEY", "chat-groq": "GROQ_API_KEY"}


def _headers(settings: AdminSettings) -> dict:
    return {"authorization": f"Bearer {settings.master_key}", "content-type": "application/json"}


def _scrub(text: str, master_key: str) -> str:
    """Remove the master key from any text that goes back to the browser."""
    return text.replace(master_key, "[redacted]") if master_key else text


router = APIRouter()


@router.get("/")
def index() -> RedirectResponse:
    # The dashboard is the home page; the staging chat page was removed.
    return RedirectResponse("/dashboard", status_code=303)


@router.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/api/models")
async def models(settings: AdminSettings = Depends(admin_settings)) -> dict:
    """The CTRL_AI_UI_MODELS names that the gateway lists and that have a provider key."""
    wanted = settings.ui_models
    keyed = set(settings.ui_keyed_models)
    try:
        async with httpx.AsyncClient(timeout=GATEWAY_TIMEOUT) as client:
            resp = await client.get(settings.gateway_url + "/v1/models", headers=_headers(settings))
        listed = {m.get("id") for m in resp.json().get("data", [])} if resp.status_code == 200 else set()
        problem = None if resp.status_code == 200 else f"gateway answered {resp.status_code} to /v1/models"
    except (httpx.HTTPError, ValueError) as exc:
        listed, problem = set(), f"gateway unreachable ({type(exc).__name__})"
    available, hidden = [], []
    for name in wanted:
        if name not in listed:
            hidden.append({"model": name, "reason": "not listed by the gateway"})
        elif name in KEYED_PROVIDER_MODELS and name not in keyed:
            hidden.append({"model": name, "reason": f"{KEYED_PROVIDER_MODELS[name]} is empty in .env"})
        else:
            available.append(name)
    message = problem
    if not available and not message:
        message = (
            "No chat model available. Put MISTRAL_API_KEY or GROQ_API_KEY in .env, "
            "list the model in CTRL_AI_UI_MODELS, and run make up again."
        )
    return {"models": available, "hidden": hidden, "message": message}


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    model: str
    messages: list[ChatMessage]


def _result(
    status: str, *, master_key: str, reply=None, message=None, rule=None, request_id=None, http_status=None
) -> dict:
    return {
        "status": status,
        "reply": reply,
        "message": _scrub(message, master_key) if message else message,
        "rule": rule,
        "request_id": request_id,
        "http_status": http_status,
    }


@router.post("/api/chat")
async def chat(body: ChatRequest, settings: AdminSettings = Depends(admin_settings)) -> dict:
    """Forward one chat turn to the gateway. Nothing about its text is logged."""
    result = functools.partial(_result, master_key=settings.master_key)
    payload = {
        "model": body.model,
        "max_tokens": MAX_TOKENS,
        "stream": False,
        "messages": [m.model_dump() for m in body.messages],
    }
    try:
        async with httpx.AsyncClient(timeout=GATEWAY_TIMEOUT) as client:
            resp = await client.post(
                settings.gateway_url + "/v1/chat/completions", json=payload, headers=_headers(settings)
            )
    except httpx.TimeoutException:
        return result("error", message="The gateway did not answer within 60 seconds.")
    except httpx.HTTPError as exc:
        return result("error", message=f"Gateway unreachable ({type(exc).__name__}).")

    request_id = resp.headers.get("x-litellm-call-id")
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if resp.status_code == 200:
        try:
            reply = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            return result(
                "error",
                message="The gateway's answer had no reply text.",
                request_id=request_id,
                http_status=200,
            )
        return result("ok", reply=reply, request_id=request_id, http_status=200)

    error = data.get("error") if isinstance(data, dict) else None
    error = error if isinstance(error, dict) else {}
    message = error.get("message")
    if not isinstance(message, str):
        message = resp.text[:500] or f"HTTP {resp.status_code}"
    if resp.status_code == 400 and BLOCK_TEXT in message:
        rule = (error.get("provider_specific_fields") or {}).get("rule")
        return result("blocked", message=message, rule=rule, request_id=request_id, http_status=400)
    return result("error", message=message[:1000], request_id=request_id, http_status=resp.status_code)


@router.get("/api/audit")
def audit(
    limit: int = Query(200, ge=1, le=5000),
    request_id: str | None = None,
    settings: AdminSettings = Depends(admin_settings),
) -> dict:
    """The newest audit records, decision and usage rows joined by request_id."""
    return {"records": audit_reader.read_records(settings.audit_log, limit, request_id)}


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
