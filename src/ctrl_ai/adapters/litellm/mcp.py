"""LiteLLM adapter for the MCP tool gateway checks.

Registered in deploy/litellm/config.yaml as a guardrail with mode [pre_mcp_call, post_mcp_call]. LiteLLM
v1.103 runs a guardrail's `apply_guardrail` on MCP calls through its MCP translation handler:
  input_type "request":  before the tool call; inputs["texts"] are the argument strings
  input_type "response": after the tool call;  inputs["texts"] are the result's text blocks
Raising an HTTPException refuses the call. Everything else fails open (our bug never blocks a
call), with the error recorded in the tool row.

Reads named fields of request_data only; never serialises it (it can carry credentials).
"""

from __future__ import annotations

import asyncio
import time
import uuid

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

from ctrl_ai.mcp import core
from ctrl_ai.pipeline.runtime import get_engine, get_settings

REFUSAL = "Blocked by ctrl-ai (MCP): {reason}{detail}"
REASON_TEXT = {
    "server_not_approved": "this MCP server is not approved",
    "team_not_allowed": "your team may not use this MCP server",
    "tool_not_allowed": "this tool is not approved",
    "description_changed": "the tool's description changed since it was approved; it is suspended until reviewed",
    "rule": "the tool call matched a policy rule",
}
_STARTS_MAX = 2048


def _get(mapping, *keys):
    """The first present key of a dict-like object (named fields only)."""
    if not hasattr(mapping, "get"):
        return None
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


class CtrlAiMCPGuardrail(CustomGuardrail):
    """Approved servers only, pinned descriptions, deterministic checks, one `tool` audit row per call."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        engine = get_engine()
        self.catalogue = core.Catalogue(get_settings().mcp_file)
        self.pins = core.PinChecker(core.http_list_tools)
        self.checker = engine.check_text
        self.audit = engine.audit
        self._starts: dict = {}

    # ------------------------------------------------------------ identity and names

    def _team(self, data) -> str:
        meta = _get(data, "metadata", "litellm_metadata") or {}
        team = _get(meta, "user_api_key_team_id", "team_id") or _get(data, "user_api_key_team_id")
        auth = _get(data, "user_api_key_auth", "user_api_key_dict")
        if not team and auth is not None:
            team = getattr(auth, "team_id", None)
        # The master key has no team: it is the platform admin.
        return team or core.ADMIN_TEAM

    def _names(self, data) -> tuple[str | None, str]:
        meta = _get(data, "mcp_tool_call_metadata") or {}
        full = _get(data, "mcp_tool_name", "name", "tool_name") or _get(meta, "name", "tool_name") or ""
        hint = _get(data, "mcp_server_name", "server_name") or _get(meta, "mcp_server_name", "server_name")
        server, tool = core.split_tool_name(str(full), self.catalogue.server_names(), hint)
        if server is None:
            owners = [
                s.get("name")
                for s in self.catalogue.load().get("servers", [])
                if any(t.get("name") == tool for t in s.get("tools") or [])
            ]
            server = owners[0] if len(owners) == 1 else None
        return server, tool

    def _call_id(self, data) -> str:
        return str(_get(data, "litellm_call_id", "call_id", "id") or uuid.uuid4())

    # ------------------------------------------------------------ hook

    async def apply_guardrail(self, inputs, request_data, input_type, logging_obj=None):
        data = request_data if request_data is not None else {}
        try:
            server, tool = self._names(data)
            team = self._team(data)
            call_id = self._call_id(data)
        except Exception as exc:
            self.audit.write(
                core.tool_row(
                    None,
                    None,
                    None,
                    None,
                    core.Verdict("allow", error=f"internal: {type(exc).__name__}"),
                    None,
                )
            )
            return inputs
        if input_type == "request":
            return await self._before(inputs, data, server, tool, team, call_id)
        return await self._after(inputs, server, tool, team, call_id)

    async def _before(self, inputs, data, server, tool, team, call_id):
        start = time.perf_counter()
        try:
            arguments = _get(data, "mcp_arguments", "arguments") or {}
            verdict = await asyncio.to_thread(
                core.decide_call, self.catalogue, self.pins, server, tool, team, arguments, self.checker
            )
        except Exception as exc:
            verdict = core.Verdict("allow", error=f"internal: {type(exc).__name__}")
        if verdict.refused:
            self.audit.write(
                core.tool_row(call_id, server, tool, team, verdict, (time.perf_counter() - start) * 1000)
            )
            detail = f" (rule {verdict.rule})" if verdict.rule else ""
            raise HTTPException(
                status_code=403,
                detail={
                    "error": REFUSAL.format(
                        reason=REASON_TEXT.get(verdict.reason or "", verdict.reason or "refused"),
                        detail=detail,
                    ),
                    "server": server,
                    "tool": tool,
                    "reason": verdict.reason,
                },
            )
        if len(self._starts) > _STARTS_MAX:
            self._starts.clear()
        self._starts[(server, tool, team)] = (start, verdict)
        return inputs

    async def _after(self, inputs, server, tool, team, call_id):
        start, before = self._starts.pop((server, tool, team), (None, None))
        try:
            verdict = core.decide_result(list((inputs or {}).get("texts") or []), team, self.checker)
        except Exception as exc:
            verdict = core.Verdict("allow", error=f"internal: {type(exc).__name__}")
        if before is not None:
            verdict.findings = before.findings + verdict.findings
            verdict.description_pinned = before.description_pinned
            verdict.error = verdict.error or before.error
            if before.decision == "flag" and verdict.decision == "allow":
                verdict.decision = "flag"
        latency = (time.perf_counter() - start) * 1000 if start else None
        self.audit.write(core.tool_row(call_id, server, tool, team, verdict, latency))
        if verdict.refused:
            detail = f" (rule {verdict.rule})" if verdict.rule else ""
            raise HTTPException(
                status_code=403,
                detail={
                    "error": REFUSAL.format(reason="the tool result matched a policy rule", detail=detail),
                    "server": server,
                    "tool": tool,
                },
            )
        return inputs
