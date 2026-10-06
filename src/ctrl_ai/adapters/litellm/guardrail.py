"""LiteLLM adapter: the pre-call guardrail the gateway loads.

Registered in the gateway config as
``guardrail: ctrl_ai.adapters.litellm.guardrail.CtrlAiGuardrail`` (mode ``pre_call``).
It runs everything deterministic and everything that changes the request.
When it refuses, it writes the decision row itself; otherwise it leaves the request
context in the context cache for the semantic hook (``adapters/litellm/semantic.py``), which runs
alongside the model call and writes the row.

``data`` holds raw credentials (``secret_fields``, ``proxy_server_request``,
``provider_specific_header``), including a user's subscription token. It is
never logged, copied or serialised here; it is only handed to the engine.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy.common_utils.callback_utils import add_guardrail_to_applied_guardrails_header

from ctrl_ai.pipeline import hooks
from ctrl_ai.pipeline.runtime import get_engine, get_settings


class CtrlAiGuardrail(CustomGuardrail):
    # No apply_guardrail method on purpose: defining one makes LiteLLM route
    # the class through its unified guardrail path instead of the hook below.

    def __init__(self, **kwargs: Any):
        # LiteLLM passes guardrail_name, event_hook, default_on and more.
        super().__init__(**kwargs)
        self.engine = get_engine()
        hooks.startup_checks(self.engine, get_settings().gateway_config_file)

    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type):
        started = time.time()
        # The deliberate refusals below are the only exceptions allowed to leave
        # this hook: anything else would become an HTTP 500 for the client.
        try:
            ctx = await hooks.before_call(self.engine, data, call_type, user_api_key_dict)
        except Exception:
            return data  # the engine already fails open; this is the last line of defence
        if ctx is None:
            return data
        decision = ctx.decision
        self._record(data, ctx, started)
        if decision == "throttle":
            raise _throttle_exception(ctx)
        if decision == "block":
            raise HTTPException(
                status_code=ctx.status_code,
                detail={"error": ctx.message, "rule": ctx.rule},
                headers=ctx.headers,
            )
        if ctx.model_routed and ctx.model_routed != data.get("model"):
            # Reroute: LiteLLM routes on data["model"] after the pre-call hooks.
            data["model"] = ctx.model_routed
        return data

    def _record(self, data: dict, ctx, started: float) -> None:
        """Make the outcome visible in LiteLLM's own records. No text, only the outcome."""
        try:
            blocked = ctx.decision in ("block", "throttle")
            if not blocked:
                # LiteLLM sets the x-litellm-applied-guardrails header itself only on a block.
                add_guardrail_to_applied_guardrails_header(
                    request_data=data, guardrail_name=self.guardrail_name
                )
            now = time.time()
            self.add_standard_logging_guardrail_information_to_request_data(
                guardrail_json_response={
                    "decision": ctx.decision,
                    "rule": ctx.rule,
                    "findings": len(ctx.findings),
                },
                request_data=data,
                guardrail_status="guardrail_intervened" if blocked else "success",
                start_time=started,
                end_time=now,
                duration=now - started,
                guardrail_provider="ctrl-ai",
            )
        except Exception:
            pass


def _throttle_exception(ctx) -> Exception:
    """A 429 with Retry-After. LiteLLM drops the headers of a guardrail's HTTPException but
    keeps those of a ProxyException (verified on v1.103.2)."""
    try:
        from litellm.proxy._types import ProxyException

        return ProxyException(
            message=ctx.message,
            type="throttle_error",
            param=None,
            code=ctx.status_code,
            headers=dict(ctx.headers or {}),
            provider_specific_fields={"rule": ctx.rule},
        )
    except Exception:
        return HTTPException(
            status_code=ctx.status_code, detail={"error": ctx.message, "rule": ctx.rule}, headers=ctx.headers
        )
