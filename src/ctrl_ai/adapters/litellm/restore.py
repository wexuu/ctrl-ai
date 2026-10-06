"""LiteLLM adapter: restore masked values in the answer, registered with ``mode: post_call``.

Looks up the request's surrogate map in the context cache (by ``litellm_call_id``); a request
without masking passes through untouched.
"""

from __future__ import annotations

from typing import Any

from litellm.integrations.custom_guardrail import CustomGuardrail

from ctrl_ai.detect.restore import restore_chat_stream, restore_response
from ctrl_ai.pipeline.runtime import get_engine


def _context(data: Any) -> Any:
    return get_engine().cache.get((data or {}).get("litellm_call_id"))


def _mapping(data: Any) -> dict:
    try:
        ctx = _context(data)
        return dict(ctx.mask_map) if ctx is not None and ctx.mask_map else {}
    except Exception:
        return {}


class CtrlAiRestoreGuardrail(CustomGuardrail):
    # No apply_guardrail method on purpose (see guardrail.py).

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)

    async def async_post_call_success_hook(self, data: dict, user_api_key_dict, response):
        mapping = _mapping(data)
        if not mapping:
            return response
        try:
            return restore_response(response, mapping)
        except Exception:
            return response

    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data: dict):
        mapping = _mapping(request_data)
        ctx = _context(request_data)
        if not mapping or ctx is None or ctx.endpoint != "chat_completions":
            async for chunk in response:
                yield chunk
            return
        async for chunk in restore_chat_stream(response, mapping):
            yield chunk
