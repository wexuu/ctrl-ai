"""MCP tool gateway checks, pure part: catalogue, pinning, allow/deny, content checks, tool rows.

No LiteLLM import here, so it is unit-testable on the host. The LiteLLM adapter is
adapters/litellm/mcp.py.

Decision for one tool call (in this order):
  1. server unknown, not approved, or not approved for the caller's team -> refuse
  2. tool not listed as allowed -> refuse
  3. tool description changed since it was pinned (rug pull) -> refuse, tool suspended
  4. deterministic checks on the arguments (the engine's check_text, source tool_call)
     and later on the result (source tool_result): block -> refuse, flag -> allow and flag
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
import yaml

PIN_TTL_S = 600  # re-list a server's tools every 10 minutes
ADMIN_TEAM = "admin"  # the master key (platform admin) may use every approved server


def tool_hash(name: str, description: str | None, input_schema) -> str:
    """SHA-256 of canonical JSON of name + description + input schema."""
    canonical = json.dumps(
        {"name": name, "description": description or "", "input_schema": input_schema or {}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hash_listed_tool(tool: dict) -> str:
    return tool_hash(
        tool.get("name", ""), tool.get("description"), tool.get("inputSchema") or tool.get("input_schema")
    )


# ---------------------------------------------------------------- catalogue


class Catalogue:
    """config/mcp.yaml, re-read when it changes; an invalid file keeps the last good one."""

    def __init__(self, path: str):
        self.path = path
        self._stamp = None
        self.doc: dict = {"servers": []}
        self.last_error: str | None = None
        self._lock = threading.Lock()

    def load(self) -> dict:
        with self._lock:
            try:
                st = os.stat(self.path)
            except OSError:
                self.doc, self._stamp = {"servers": []}, None
                return self.doc
            stamp = (st.st_mtime_ns, st.st_size)
            if stamp != self._stamp:
                try:
                    with open(self.path, encoding="utf-8") as f:
                        doc = yaml.safe_load(f)
                    if not isinstance(doc, dict) or not isinstance(doc.get("servers", []), list):
                        raise ValueError("not a mapping with servers")
                    self.doc, self.last_error = doc, None
                except (OSError, ValueError, yaml.YAMLError) as exc:
                    self.last_error = f"{type(exc).__name__}"
                self._stamp = stamp
            return self.doc

    def server(self, name: str) -> dict | None:
        for s in self.load().get("servers", []) or []:
            if isinstance(s, dict) and s.get("name") == name:
                return s
        return None

    def server_names(self) -> list[str]:
        servers = self.load().get("servers", []) or []
        return [s["name"] for s in servers if isinstance(s, dict) and isinstance(s.get("name"), str)]


def split_tool_name(
    full_name: str, server_names: list[str], server_hint: str | None = None
) -> tuple[str | None, str]:
    """LiteLLM prefixes tool names with the server name ("<server>-<tool>"). Returns (server, tool)."""
    if server_hint and full_name.startswith(server_hint + "-"):
        return server_hint, full_name[len(server_hint) + 1 :]
    for name in sorted(server_names, key=len, reverse=True):
        for sep in ("-", "__", "/"):
            if full_name.startswith(name + sep):
                return name, full_name[len(name) + len(sep) :]
    return server_hint, full_name


# ---------------------------------------------------------------- pin checker


@dataclass
class PinState:
    """The listed tools of one server, fetched at most every PIN_TTL_S seconds."""

    fetched_at: float = 0.0
    hashes: dict = field(default_factory=dict)  # tool name -> current description hash
    error: str | None = None

    def error_or(self, default: str) -> str:
        return self.error or default


class PinChecker:
    """Compares the live tool descriptions with the pinned hashes in the catalogue."""

    def __init__(self, lister, ttl: float = PIN_TTL_S, clock=time.monotonic):
        self.lister = lister  # callable(server_dict) -> list of tool dicts (name, description, inputSchema)
        self.ttl = ttl
        self.clock = clock
        self.state: dict[str, PinState] = {}

    def current(self, server: dict) -> PinState:
        name = server.get("name") or ""
        st = self.state.get(name)
        if st is None or self.clock() - st.fetched_at >= self.ttl:
            st = PinState(fetched_at=self.clock())
            try:
                st.hashes = {t.get("name"): hash_listed_tool(t) for t in self.lister(server)}
            except Exception as exc:
                st.error = f"list_tools failed: {type(exc).__name__}"
            self.state[name] = st
        return st

    def status(self, server: dict, tool: str) -> str:
        """pinned (hash matches), changed (mismatch), unpinned (no pin), unknown (cannot list)."""
        entry = next((t for t in server.get("tools") or [] if t.get("name") == tool), None)
        pin = entry.get("description_sha256") if entry else None
        if not pin:
            return "unpinned"
        st = self.current(server)
        if st.error or tool not in st.hashes:
            return "unknown"
        return "pinned" if st.hashes[tool] == pin else "changed"


def http_list_tools(server: dict, timeout: float = 5.0) -> list[dict]:
    """tools/list over MCP streamable HTTP (JSON-RPC POST); works with stateless servers."""
    url = server.get("url") or ""
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    with httpx.Client(timeout=timeout) as client:
        init = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ctrl-ai-pin-check", "version": "1"},
            },
        }
        resp = client.post(url, json=init, headers=headers)
        session = resp.headers.get("mcp-session-id")
        if session:
            headers["mcp-session-id"] = session
            client.post(url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers)
        resp = client.post(
            url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, headers=headers
        )
        return _jsonrpc_result(resp).get("tools", [])


def _jsonrpc_result(resp) -> dict:
    text = resp.text
    if "text/event-stream" in resp.headers.get("content-type", ""):
        for line in text.splitlines():
            if line.startswith("data:"):
                text = line[5:].strip()
                break
    body = json.loads(text)
    if "error" in body:
        raise RuntimeError(str(body["error"].get("message", "error"))[:200])
    return body.get("result") or {}


# ---------------------------------------------------------------- content checks


Checker = Callable[..., dict]


def check_text(text: str, source: str, team: str | None, checker: Checker | None) -> dict:
    """The gateway's deterministic text check (``Engine.check_text``); without one, allow and say so."""
    if checker is None:
        return {
            "decision": "allow",
            "findings": [],
            "normalisation": {},
            "data_class_detected": "public",
            "policy_version": None,
            "error": "not_installed",
        }
    try:
        result = checker(text, source=source, team=team)
        return (
            result
            if isinstance(result, dict)
            else {"decision": "allow", "findings": [], "error": "internal: bad result"}
        )
    except Exception as exc:
        return {"decision": "allow", "findings": [], "error": f"internal: {type(exc).__name__}"}


# ---------------------------------------------------------------- decisions


@dataclass
class Verdict:
    decision: str  # allow | block | flag
    reason: str | None = (
        None  # server_not_approved, team_not_allowed, tool_not_allowed, description_changed, rule
    )
    findings: list = field(default_factory=list)
    description_pinned: bool | None = None
    error: str | None = None
    rule: str | None = None

    @property
    def refused(self) -> bool:
        return self.decision == "block"


def decide_call(
    catalogue: Catalogue,
    pins: PinChecker | None,
    server_name: str | None,
    tool: str,
    team: str | None,
    arguments,
    checker: Checker | None = None,
) -> Verdict:
    server = catalogue.server(server_name) if server_name else None
    if server is None or server.get("status") != "approved":
        return Verdict("block", "server_not_approved")
    teams = server.get("teams") or []
    if team != ADMIN_TEAM and "*" not in teams and team not in teams:
        return Verdict("block", "team_not_allowed")
    entry = next((t for t in server.get("tools") or [] if t.get("name") == tool), None)
    if not entry or not entry.get("allowed"):
        return Verdict("block", "tool_not_allowed")
    pinned, pin_error = None, None
    if pins is not None:
        status = pins.status(server, tool)
        if status == "changed":
            return Verdict("block", "description_changed", description_pinned=False)
        pinned = status == "pinned"
        if status == "unknown":
            # Cannot list the server's tools right now: allowed (fail open), recorded in the row.
            pin_error = "pin_check: " + (pins.state.get(server.get("name") or "") or PinState()).error_or(
                "tool not listed"
            )
    text = (
        arguments
        if isinstance(arguments, str)
        else json.dumps(arguments or {}, ensure_ascii=False, sort_keys=True)
    )
    res = check_text(text, "tool_call", team, checker)
    v = _from_check(res)
    v.description_pinned = pinned
    if pin_error:
        v.error = f"{pin_error}; {v.error}" if v.error else pin_error
    return v


def decide_result(texts: list[str], team: str | None, checker: Checker | None = None) -> Verdict:
    res = check_text("\n".join(t for t in texts if isinstance(t, str)), "tool_result", team, checker)
    return _from_check(res)


def _from_check(res: dict) -> Verdict:
    findings = [
        {k: f.get(k) for k in ("rule", "pack", "source", "action", "severity")}
        for f in res.get("findings") or []
        if isinstance(f, dict)
    ]
    raw = res.get("decision")
    decision = raw if isinstance(raw, str) and raw in ("allow", "block", "flag") else "allow"
    rule = next((f["rule"] for f in findings if f.get("action") == "block"), None)
    return Verdict(
        decision, "rule" if decision == "block" else None, findings, error=res.get("error"), rule=rule
    )


# ---------------------------------------------------------------- audit rows


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def tool_row(request_id, server, tool, team, verdict: Verdict, latency_ms) -> dict:
    row = {
        "type": "tool",
        "v": 2,
        "ts": now_iso(),
        "request_id": request_id,
        "server": server,
        "tool": tool,
        "team": team,
        "decision": verdict.decision,
        "findings": verdict.findings,
        "latency_ms": None if latency_ms is None else round(latency_ms, 1),
        "description_pinned": verdict.description_pinned,
    }
    if verdict.reason:
        row["reason"] = verdict.reason
    if verdict.error:
        row["error"] = verdict.error
    return row
