"""LiteLLM adapter: custom auth (``general_settings.custom_auth``).

Replaces LiteLLM's key check. The master key keeps working; every other key must be in
``state/keys.json`` (as a SHA-256 hash), not revoked and not expired. A failure gives HTTP
401 "Invalid or revoked ctrl-ai key". The raw key is never stored or logged.

LiteLLM passes the gateway key here: from ``x-litellm-api-key`` when present (which wins over
``Authorization``, so a forwarded Claude subscription token is never treated as the key),
else ``Authorization: Bearer``, else ``x-api-key``.
"""

from __future__ import annotations

from fastapi import Request
from litellm.proxy._types import ProxyErrorTypes, ProxyException, UserAPIKeyAuth

from ctrl_ai.governance.identity import INVALID_KEY_MESSAGE, authenticate, hash_key
from ctrl_ai.governance.routes import route_from_authorization
from ctrl_ai.pipeline.runtime import get_engine, get_key_store, get_settings


async def user_api_key_auth(request: Request, api_key: str) -> UserAPIKeyAuth:
    result = authenticate(
        api_key, get_settings().master_key, get_key_store().current(), get_engine().teams.current()
    )
    if result.identity is None:
        raise ProxyException(
            message=INVALID_KEY_MESSAGE, type=ProxyErrorTypes.auth_error, param="api_key", code=401
        )
    ident = result.identity
    # Prefix check only: is a Claude subscription token being forwarded?
    route = route_from_authorization(request.headers.get("authorization"))
    if result.key_hash is None:
        # The master key: LiteLLM's own admin identity, so admin routes keep working.
        return UserAPIKeyAuth(
            api_key=hash_key(api_key),
            user_role="proxy_admin",
            metadata={
                "ctrl_ai_department": ident.department,
                "ctrl_ai_profile": None,
                "ctrl_ai_admin": True,
                "ctrl_ai_route": route,
            },
            team_id=ident.team,
        )
    metadata = {
        "ctrl_ai_department": ident.department,
        "ctrl_ai_profile": ident.profile,
        "ctrl_ai_mode": ident.mode,
        "ctrl_ai_route": route,
    }
    if ident.error:
        metadata["ctrl_ai_identity_error"] = ident.error
    return UserAPIKeyAuth(
        api_key=result.key_hash,
        user_id=ident.user,
        team_id=ident.team,
        key_alias=ident.key_id,
        metadata=metadata,
    )
