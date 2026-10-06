"""Loop counters, escalation, identical tool calls, fail-open."""

from __future__ import annotations

import asyncio

from ctrl_ai.detect.extract import latest_prompt_text, session_header, tool_call_signature
from ctrl_ai.governance import loops
from tests.unit.fake_state import FakeState

LIMITS = {
    "max_requests_per_10_min": 10,
    "max_tokens_per_session": 1000,
    "max_calls_per_user_turn": 100,
    "max_identical_tool_calls": 3,
}


def check(state, session="s", prompt="p", tool=None, now=1000.0):
    return asyncio.run(loops.check(state, session, prompt, tool, LIMITS, now))


def test_escalation_warn_throttle_stop():
    state = FakeState()
    states = [(check(state) or {}).get("state") for _ in range(16)]
    assert states[:7] == [None] * 7
    assert states[7:10] == ["warn"] * 3  # 8, 9, 10 of 10
    assert states[10:15] == ["throttle"] * 5  # 11..15
    assert states[15] == "stop"  # 16 > 150%
    again = check(state)
    assert again["state"] == "stop" and again["kind"] == "stopped_session"


def test_sessions_are_independent():
    state = FakeState()
    for _ in range(11):
        check(state, session="a")
    assert check(state, session="b") is None


def test_tokens_counted_from_the_logger():
    state = FakeState()
    asyncio.run(loops.add_tokens(state, "s", 900))
    assert check(state)["kind"] == "tokens_per_session"
    asyncio.run(loops.add_tokens(state, "s", 200))
    assert check(state)["state"] == "throttle"


def test_identical_tool_calls_stop_the_session():
    state = FakeState()
    assert check(state, tool="A") is None
    assert check(state, tool="A") is None  # 2 of 3 is below 80%
    out = check(state, tool="A")
    assert out["state"] == "stop" and out["kind"] == "identical_tool_calls"


def test_different_tool_calls_reset_the_run():
    state = FakeState()
    for tool in ("A", "A", "B", "A", "B"):
        out = check(state, tool=tool, session="t")
        assert out is None or out["state"] != "stop"


def test_redis_down_fails_open_once_a_minute():
    state = FakeState()
    state.down = True
    loops._last_unavailable[0] = 0.0
    assert check(state, now=10_000.0) == {"state": "unavailable", "counter": None, "limit": None}
    assert check(state, now=10_010.0) is None
    assert check(state, now=10_061.0)["state"] == "unavailable"


def test_session_identity():
    assert loops.session_id("abc", None, "k_1", 0) == "cc:abc"
    assert loops.session_id(None, "ls1", "k_1", 0) == "ls:ls1"
    assert loops.session_id(None, None, None, 1200) == "key:admin:2"


def test_extract_helpers():
    data = {
        "proxy_server_request": {"headers": {"x-claude-code-session-id": "sess-1"}},
        "messages": [
            {"role": "user", "content": "fix the bug"},
            {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t", "name": "Bash", "input": {"cmd": "ls"}}],
            },
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "ok"}]},
        ],
    }
    assert session_header(data) == "sess-1"
    assert latest_prompt_text(data) == "fix the bug"
    assert tool_call_signature(data) == '[["Bash", "{\\"cmd\\":\\"ls\\"}"]]'


def test_messages_name_the_problem():
    assert "unusually fast (11 requests in 10 minutes, limit 10)" in loops.message(
        {"state": "throttle", "counter": 11, "limit": 10, "kind": "requests_per_10_min"}
    )
    assert "same tool call repeated 3 times" in loops.message(
        {"state": "stop", "counter": 3, "limit": 3, "kind": "identical_tool_calls"}
    )


def test_agent_session_timeout_stops_the_session():
    from ctrl_ai.governance import loops as _loops

    state = FakeState()
    limits = {
        "max_requests_per_10_min": 300,
        "max_tokens_per_session": 2_000_000,
        "max_calls_per_user_turn": 80,
        "max_identical_tool_calls": 5,
        "max_session_minutes": 10,
    }
    assert asyncio.run(_loops.check(state, "s1", "hi", None, limits, now=1000.0)) is None
    late = asyncio.run(_loops.check(state, "s1", "hi again", None, limits, now=1000.0 + 11 * 60))
    assert late["state"] == "stop" and late["kind"] == "session_time"
    assert "agent timeout" in _loops.message(late)
