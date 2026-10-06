"""The HTTP call to Jev. One request per call, no retries: a live request waits on it."""

from __future__ import annotations

import logging
import time

import httpx

from ctrl_ai.core.settings import JevSettings, jev_settings_from_env
from ctrl_ai.semantic.jev.questions import build_request, question_ids
from ctrl_ai.semantic.jev.verdict import normalise, verdict

log = logging.getLogger("ctrl_ai.semantic.jev")

MAX_TEXT_CHARS = 20_000


async def check_text(
    text: str,
    *,
    source: str = "prompt",
    timeout_s: float | None = None,
    settings: JevSettings | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict:
    """Ask Jev whether ``text`` is an attack on an AI agent.

    Never raises; always returns the nine-key verdict. Without ``settings`` the JEV_*
    variables are read now. ``transport`` exists only so tests can inject ``httpx.MockTransport``.
    """
    start = time.perf_counter()
    truncated = False
    try:
        settings = settings if settings is not None else jev_settings_from_env()
        if not settings.api_key:
            return verdict("disabled", latency_ms=0.0)

        if not isinstance(text, str):
            text = str(text)
        if len(text) > MAX_TEXT_CHARS:
            text = text[:MAX_TEXT_CHARS]
            truncated = True

        limit = timeout_s if timeout_s is not None and timeout_s > 0 else settings.timeout_s
        body = build_request(text, settings.model, source)
        headers = {
            "Authorization": f"Bearer {settings.api_key}",
            "Content-Type": "application/json",
        }
        # A fresh client per call keeps concurrent calls independent and leaves no
        # connection pool bound to an event loop that may be closed later.
        async with httpx.AsyncClient(timeout=httpx.Timeout(limit), transport=transport) as client:
            resp = await client.post(settings.url, json=body, headers=headers)
        latency_ms = (time.perf_counter() - start) * 1000
        try:
            parsed = resp.json()
        except ValueError:
            parsed = None
        result = normalise(resp.status_code, parsed, latency_ms, question_ids(source), truncated=truncated)
    except httpx.TimeoutException:
        result = _failure("unavailable", "timeout", start, truncated)
    except httpx.TransportError:
        # Covers ConnectError (DNS, refused, TLS) and broken connections mid-request.
        result = _failure("unavailable", "connect", start, truncated)
    except Exception as exc:
        log.warning("jev check failed: internal %s", type(exc).__name__)
        result = _failure("error", "internal", start, truncated)

    if result["status"] != "ok":
        # Status and reason only: an error body can echo the input text.
        log.info("jev check: %s %s", result["status"], result["error"])
    return result


def _failure(status: str, error: str, start: float, truncated: bool) -> dict:
    return verdict(
        status,
        error=error,
        latency_ms=(time.perf_counter() - start) * 1000,
        truncated=truncated,
    )
