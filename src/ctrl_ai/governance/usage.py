"""The usage row, built from LiteLLM's standard logging object.

Pure: no LiteLLM import. The adapter ``adapters/litellm/logger.py`` hands in the
``standard_logging_object`` (which holds no credentials), the request context from
the context cache (joined by request id) and the model catalogue.
"""

from __future__ import annotations

from typing import Any

from ctrl_ai.core.audit import utc_now_iso
from ctrl_ai.core.context import RequestContext
from ctrl_ai.core.rows import usage_fields

_ROUTE_ENDPOINTS = (
    ("/messages", "messages"),
    ("/chat/completions", "chat_completions"),
    ("/responses", "responses"),
)


def endpoint_from_route(route: Any) -> str:
    # The route, not call_type: on failed /v1/messages requests LiteLLM
    # reports call_type as acompletion.
    if isinstance(route, str):
        for fragment, endpoint in _ROUTE_ENDPOINTS:
            if fragment in route:
                return endpoint
    return "unknown"


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def cost_fields(
    model_routed: str | None, input_tokens: Any, output_tokens: Any, litellm_cost: Any, catalogue: Any = None
) -> dict:
    """Cost of a call: catalogue price first, else LiteLLM's figure, else unknown."""
    entry = None
    if catalogue is not None and model_routed:
        try:
            entry = catalogue.lookup(model_routed)
        except Exception:
            entry = None
    provider = getattr(entry, "provider", None)
    price = getattr(entry, "price", None)
    tokens_in = int(_number(input_tokens) or 0)
    tokens_out = int(_number(output_tokens) or 0)
    if price is not None:
        cost = tokens_in * price.input_per_mtok / 1e6 + tokens_out * price.output_per_mtok / 1e6
        return {
            "provider": provider,
            "price_known": True,
            "cost_usd": round(cost, 8),
            "cost_source": "catalogue",
            "shadow": bool(price.shadow),
        }
    if tokens_in == 0 and tokens_out == 0:
        # Nothing was used (a refused request): the cost is known to be zero.
        return {
            "provider": provider,
            "price_known": True,
            "cost_usd": 0.0,
            "cost_source": "catalogue" if entry is not None else "litellm",
            "shadow": False,
        }
    lite = _number(litellm_cost)
    if lite is not None and lite > 0:
        return {
            "provider": provider,
            "price_known": True,
            "cost_usd": lite,
            "cost_source": "litellm",
            "shadow": False,
        }
    return {
        "provider": provider,
        "price_known": False,
        "cost_usd": None,
        "cost_source": "unknown",
        "shadow": False,
    }


def build_usage_row(slo: dict, ctx: RequestContext | None = None, catalogue: Any = None) -> dict | None:
    """Build the usage row, or None for a route that is not a model endpoint.

    LiteLLM also calls the logger for auth failures on routes such as
    ``/v1/models``; those are not usage.
    """
    endpoint = endpoint_from_route((slo.get("metadata") or {}).get("user_api_key_request_route"))
    if endpoint == "unknown":
        return None
    status = slo.get("status")
    error = None
    if status != "success":
        info = slo.get("error_information") or {}
        error = f"{info.get('error_class') or ''}:{info.get('error_code') or ''}"
    served = slo.get("model_group") or slo.get("model")
    row = {
        "type": "usage",
        "v": 2,
        "ts": utc_now_iso(),
        "request_id": slo.get("litellm_call_id"),
        "endpoint": endpoint,
        "model": served,
        "stream": slo.get("stream") is True,
        "status": status,
        "input_tokens": slo.get("prompt_tokens"),
        "output_tokens": slo.get("completion_tokens"),
        "cost_usd": slo.get("response_cost"),
        "total_ms": round((slo.get("response_time") or 0) * 1000, 1),
        "error": error,
    }
    row.update(usage_fields(ctx))
    if row["model_requested"] is None:
        row["model_requested"] = served
    if row["model_routed"] is None:
        row["model_routed"] = served
    # A fallback: LiteLLM served the request from another model group than the one we routed to.
    fallback_used = bool(
        ctx is not None
        and status == "success"
        and served
        and row["model_routed"]
        and served != row["model_routed"]
    )
    priced_model = served if fallback_used else row["model_routed"]
    row.update(
        cost_fields(
            priced_model,
            slo.get("prompt_tokens"),
            slo.get("completion_tokens"),
            slo.get("response_cost"),
            catalogue,
        )
    )
    row["fallback_used"] = fallback_used
    return row
