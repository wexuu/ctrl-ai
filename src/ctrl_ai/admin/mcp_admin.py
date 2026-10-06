"""MCP tool servers for the admin panel: live tool list, pin status, re-pin.

Listing and hashing are the gateway's own (``ctrl_ai.mcp.core``), so a pin the panel records is
exactly what the gateway checks.
"""

from __future__ import annotations

from ctrl_ai.admin import config_store
from ctrl_ai.admin.config_store import StoreError
from ctrl_ai.admin.settings import AdminSettings
from ctrl_ai.mcp.core import hash_listed_tool, http_list_tools


def list_tools(url: str) -> list[dict]:
    """The server's tools/list answer."""
    return http_list_tools({"url": url}, timeout=4.0)


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
        current = hash_listed_tool(lt) if lt else None
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
    new_hash = hash_listed_tool(live[tool])
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
