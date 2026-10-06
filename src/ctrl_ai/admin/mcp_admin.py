"""MCP tool servers for the admin panel: live tool list, pin status, re-pin.

The hash must match ctrl_ai.mcp.core.tool_hash (the gateway side); the two small functions are
repeated here so the admin panel does not import the gateway side, and a unit test keeps them equal.
"""

from __future__ import annotations

import hashlib
import json

import httpx

from ctrl_ai.admin import config_store
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.settings import AdminSettings


def tool_hash(name: str, description: str | None, input_schema) -> str:
    canonical = json.dumps(
        {"name": name, "description": description or "", "input_schema": input_schema or {}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def list_tools(url: str, timeout: float = 4.0) -> list[dict]:
    """tools/list over MCP streamable HTTP (JSON-RPC POST)."""
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    with httpx.Client(timeout=timeout) as client:
        init = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ctrl-ai-admin", "version": "1"},
            },
        }
        resp = client.post(url, json=init, headers=headers)
        if resp.headers.get("mcp-session-id"):
            headers["mcp-session-id"] = resp.headers["mcp-session-id"]
            client.post(url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers)
        resp = client.post(
            url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, headers=headers
        )
        text = resp.text
        if "text/event-stream" in resp.headers.get("content-type", ""):
            text = next((ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")), "{}")
        return (json.loads(text).get("result") or {}).get("tools", [])


def server_view(server: dict, lister=list_tools) -> dict:
    """The server as the panel shows it: every pinned or live tool with its pin status."""
    out = {k: server.get(k) for k in ("name", "url", "transport", "status", "owner", "teams")}
    live, error = {}, None
    try:
        live = {t.get("name"): t for t in lister(server.get("url"))}
    except Exception as exc:
        error = f"cannot list tools ({type(exc).__name__})"
    tools = []
    configured = {t.get("name"): t for t in server.get("tools") or []}
    for name in list(configured) + [n for n in live if n not in configured]:
        cfg = configured.get(name, {})
        lt = live.get(name)
        current = tool_hash(name, lt.get("description"), lt.get("inputSchema")) if lt else None
        pin = cfg.get("description_sha256")
        if not pin:
            status = "unpinned"
        elif current is None:
            status = "unknown"
        else:
            status = "pinned" if current == pin else "changed"
        tools.append(
            {
                "name": name,
                "allowed": bool(cfg.get("allowed")),
                "configured": name in configured,
                "description": lt.get("description") if lt else None,
                "pin": pin,
                "current": current,
                "pin_status": status,
            }
        )
    out["tools"] = tools
    out["error"] = error
    return out


def repin(
    settings: AdminSettings, server_name: str, tool: str, *, actor: str, reason: str, lister=list_tools
) -> str:
    """Record the tool's current description hash as the new pin (after review)."""
    doc, _, version = config_store.read(settings, "mcp")
    server = next((s for s in doc.get("servers", []) if s.get("name") == server_name), None)
    if server is None:
        raise StoreError(404, f"server {server_name} not found")
    live = {t.get("name"): t for t in lister(server.get("url"))}
    if tool not in live:
        raise StoreError(409, f"the server does not list a tool named {tool}")
    new_hash = tool_hash(tool, live[tool].get("description"), live[tool].get("inputSchema"))
    tools = server.setdefault("tools", [])
    entry = next((t for t in tools if t.get("name") == tool), None)
    if entry is None:
        entry = {"name": tool, "allowed": False}
        tools.append(entry)
    entry["description_sha256"] = new_hash
    return config_store.save(
        settings,
        "mcp",
        doc,
        expected_version=version,
        actor=actor,
        reason=f"re-pin {server_name}/{tool}: {reason}",
        action="mcp.repin",
    )
