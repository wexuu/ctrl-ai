"""Glue between the LiteLLM hooks of one request, without importing LiteLLM.

The adapters stay thin and call these functions with the engine, so the logic is
unit-testable on the host. One decision row per request:
  pre-call refuses        → pre-call writes it
  pre-call allows         → the semantic (during-call) hook completes the context and writes it
  semantic hook never ran → the logger writes it, marked ``semantic.reason: not_run``
"""

from __future__ import annotations

import os
import sys
from typing import Any

import yaml

from ctrl_ai.core.context import RequestContext
from ctrl_ai.governance import budgets, loops
from ctrl_ai.governance.identity import resolve, route_hint
from ctrl_ai.governance.usage import build_usage_row
from ctrl_ai.pipeline.engine import Engine


async def before_call(
    engine: Engine,
    data: dict,
    call_type: str | None,
    user_api_key_dict: Any,  # LiteLLM's UserAPIKeyAuth; only its metadata and ids are read
) -> RequestContext:
    """Pre-call: the deterministic half. Writes the row on a refusal, else caches the context."""
    ctx = await engine.pre_call(
        data,
        call_type=call_type,
        request_id=data.get("litellm_call_id"),
        identity=resolve(user_api_key_dict),
        route=route_hint(user_api_key_dict),
    )
    if ctx.decision in ("block", "throttle") or ctx.policy is None:
        engine.finish(ctx)
    else:
        ctx.semantic_pending = True
        engine.cache.put(ctx.request_id, ctx)
    return ctx


async def during_call(engine: Engine, data: dict, **checks) -> RequestContext | None:
    """During-call: the semantic half, then the decision row."""
    ctx = engine.cache.get(data.get("litellm_call_id"))
    if ctx is None or not ctx.semantic_pending or ctx.row_written:
        return None
    ctx.semantic_pending = False
    await engine.semantic_call(ctx, **checks)
    engine.finish(ctx)
    return ctx


async def after_call(engine: Engine, slo: dict) -> dict | None:
    """Logger: the fallback decision row if the semantic hook never ran, then the usage row."""
    ctx = engine.cache.get(slo.get("litellm_call_id"))
    if ctx is not None and ctx.semantic_pending and not ctx.row_written:
        ctx.semantic = {"source": None, "score": None, "action": "observe", "reason": "not_run"}
        engine.finish(ctx)
    row = build_usage_row(slo, ctx, engine.catalogue.current())
    if row is not None:
        engine.audit.write(row)
        await _reconcile(engine, ctx, row)
    return row


async def _reconcile(engine: Engine, ctx: RequestContext | None, row: dict) -> None:
    """After the call: tokens for the session's loop cap, actual cost for the budget."""
    if ctx is None:
        return
    try:
        tokens = int(row.get("input_tokens") or 0) + int(row.get("output_tokens") or 0)
        if ctx.session:
            await loops.add_tokens(engine.state, ctx.session, tokens)
        if ctx.budget_month and ctx.identity.team:
            # A fallback logs a failure and a success under one id: release the reservation once.
            reserved, ctx.reserved_usd = ctx.reserved_usd, 0.0
            await budgets.reconcile(
                engine.state, ctx.identity.team, ctx.budget_month, reserved, row.get("cost_usd"), tokens
            )
    except Exception:
        pass


def startup_checks(engine: Engine, gateway_config_file: str) -> None:
    """Warn when the router's fallback chains and the catalogue's ``fallbacks`` disagree.

    LiteLLM reads ``router_settings.fallbacks`` at start-up only; the catalogue is live.
    """
    try:
        if not os.path.exists(gateway_config_file):
            return
        with open(gateway_config_file, encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
        router = {}
        for item in (config.get("router_settings") or {}).get("fallbacks") or []:
            if isinstance(item, dict):
                router.update({k: list(v) for k, v in item.items()})
        cat = engine.catalogue.current()
        if not cat.loaded:
            return
        wanted = {m.id: list(m.fallbacks) for m in cat.models if m.fallbacks}
        if wanted != router:
            print(
                "ctrl-ai: WARNING router fallbacks in deploy/litellm/config.yaml differ from "
                "config/models.yaml; LiteLLM reads fallbacks at start-up only, restart the gateway "
                "after changing them",
                file=sys.stderr,
            )
    except Exception:
        pass
