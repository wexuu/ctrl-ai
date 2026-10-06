"""MCP tool calls through the gateway: allowed, refused, suspended on a changed description, audited."""

from __future__ import annotations

import httpx
import pytest

from tests.e2e import harness as h

MCP_FILE = h.RUNTIME / "mcp.yaml"


def _headers():
    return h.bearer_headers()


@pytest.fixture(scope="module")
def server_id(stack):
    resp = httpx.get(h.BASE_URL + "/mcp-rest/tools/list", headers=_headers(), timeout=30)
    assert resp.status_code == 200, resp.text[:300]
    tools = resp.json()["tools"]
    assert {t["name"] for t in tools} >= {"get_issue", "read_page", "export_customers"}
    # Two servers are registered (tickets, confluence): use the one that owns the ticket tools.
    return next(t["mcp_info"]["server_id"] for t in tools if t["name"] == "get_issue")


def _call(server_id, name, arguments):
    return httpx.post(
        h.BASE_URL + "/mcp-rest/tools/call",
        headers=_headers(),
        timeout=30,
        json={"server_id": server_id, "name": name, "arguments": arguments},
    )


def _tool_row(offset, tool):
    return h.wait_for_row(lambda r: r.get("type") == "tool" and r.get("tool") == tool, offset)


def test_allowed_tool_call_is_audited(server_id, audit_start):
    resp = _call(server_id, "get_issue", {"key": "PAY-123"})
    assert resp.status_code == 200 and "PAY-123" in resp.text
    row = _tool_row(audit_start, "get_issue")
    assert row["server"] == "tickets" and row["decision"] == "allow" and row["description_pinned"] is True
    assert set(row) >= {
        "ts",
        "request_id",
        "server",
        "tool",
        "team",
        "decision",
        "findings",
        "latency_ms",
        "description_pinned",
    }


def test_unapproved_tool_is_refused(server_id, audit_start):
    resp = _call(server_id, "export_customers", {})
    assert resp.status_code == 403 and "not approved" in resp.text
    row = _tool_row(audit_start, "export_customers")
    assert row["decision"] == "block" and row["reason"] == "tool_not_allowed"


def test_changed_description_suspends_tool(server_id, audit_start):
    original = MCP_FILE.read_text(encoding="utf-8")
    try:
        # The pin no longer matches what the server lists: the same check a rug pull triggers.
        MCP_FILE.write_text(
            original.replace("c247a197280f9c34e391693c429a57a89a34cb4d3305c3524a769fda5d954d28", "f" * 64),
            encoding="utf-8",
        )
        resp = _call(server_id, "get_issue", {"key": "PAY-9"})
        assert resp.status_code == 403 and "description changed" in resp.text
        row = _tool_row(audit_start, "get_issue")
        assert row["decision"] == "block" and row["description_pinned"] is False
    finally:
        MCP_FILE.write_text(original, encoding="utf-8")


def test_admin_page_shows_pin_status(admin):
    servers = admin.get("/api/admin/mcp").json()["servers"]
    tools = {t["name"]: t for t in servers[0]["tools"]}
    assert tools["get_issue"]["pin_status"] == "pinned" and tools["export_customers"]["allowed"] is False


def test_injected_page_is_flagged_or_blocked(server_id, audit_start):
    resp = _call(server_id, "read_page", {"title": "INJECT release notes"})
    row = _tool_row(audit_start, "read_page")
    assert resp.status_code == 403 or row["decision"] in ("flag", "block")
    assert row["findings"] and row.get("error") != "not_installed"
