"""LiteLLM adapter: the semantic check, run alongside the model call.

Registered as a second guardrail with ``mode: during_call``. LiteLLM runs
``async_moderation_hook`` in parallel with the upstream call and holds the response until
it finishes, so the user waits ``max(model, semantic)`` instead of their sum. It picks up
the request context the pre-call hook left in the context cache, asks Jev (and the judge),
writes the one decision row, and refuses with HTTP 400 when the profile says so.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

from ctrl_ai.pipeline import hooks
from ctrl_ai.pipeline.runtime import get_engine


class CtrlAiSemanticGuardrail(CustomGuardrail):
    # No apply_guardrail method on purpose (see guardrail.py).

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.engine = get_engine()

    async def async_moderation_hook(self, data: dict, user_api_key_dict, call_type):
        try:
            ctx = await hooks.during_call(self.engine, data)
        except Exception:
            return None
        if ctx is not None and ctx.decision == "block":
            raise HTTPException(status_code=ctx.status_code, detail={"error": ctx.message, "rule": ctx.rule})
        return None
