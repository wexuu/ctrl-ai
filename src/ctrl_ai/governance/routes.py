"""Which route a request takes: a forwarded Claude subscription, or external.

Checks presence and prefix of the client's Authorization header only; never copies,
logs or hashes its value. Verified on v1.103.2: inside the pre-call hook the header in
``proxy_server_request`` is already masked and ``secret_fields.raw_headers`` is empty, so the
decision is made in our custom auth (``adapters/litellm/auth.py``), which sees the real request, and
handed to the hooks in ``user_api_key_dict.metadata["ctrl_ai_route"]``. ``route_of(data)`` is the
fallback when that is missing.
"""

from __future__ import annotations

OAUTH_PREFIX = "Bearer sk-ant-oat"


def _authorization(headers) -> str | None:
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == "authorization" and isinstance(value, str):
            return value
    return None


def route_from_authorization(value) -> str:
    """The route from the raw Authorization header value (prefix check only)."""
    if isinstance(value, str) and value.startswith(OAUTH_PREFIX):
        return "claude_subscription"
    return "external"


def route_of(data: dict) -> str:
    """``claude_subscription`` when the client sent an ``sk-ant-oat`` bearer, else ``external``."""
    try:
        headers = (data.get("proxy_server_request") or {}).get("headers")
        value = _authorization(headers)
        if value is None:
            # LiteLLM strips credentials from proxy_server_request; the raw header is only in
            # secret_fields (verified on v1.103.2). Presence and prefix are read, nothing else.
            raw = getattr(data.get("secret_fields"), "raw_headers", None)
            if raw is None and isinstance(data.get("secret_fields"), dict):
                raw = data["secret_fields"].get("raw_headers")
            value = _authorization(raw)
        if value is not None and value.startswith(OAUTH_PREFIX):
            return "claude_subscription"
    except Exception:
        pass
    return "external"
