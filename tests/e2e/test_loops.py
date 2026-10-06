"""Loop caps warn, throttle (429 + Retry-After), stop; Redis down fails open."""

from __future__ import annotations

import time
import uuid

import yaml

from tests.e2e import harness as h


def small_limits(policy_text: str, **limits) -> str:
    doc = yaml.safe_load(policy_text)
    doc["loops"] = {
        "enabled": True,
        "max_requests_per_10_min": 5,
        "max_tokens_per_session": 10_000_000,
        "max_calls_per_user_turn": 1000,
        "max_identical_tool_calls": 50,
        **limits,
    }
    return yaml.safe_dump(doc, sort_keys=False)


def session_headers() -> dict:
    return {**h.bearer_headers(), "x-claude-code-session-id": "e2e-" + uuid.uuid4().hex}


def test_warn_throttle_stop(set_policy, original_policy):
    set_policy(small_limits(original_policy))
    headers = session_headers()
    seen = []
    for i in range(1, 9):
        offset = h.audit_offset()
        resp = h.post_messages(h.messages_body(f"loop step {i} {h.tag()}"), headers)
        row = h.decision_row(resp, offset)
        seen.append((resp.status_code, (row["loop"] or {}).get("state"), row["decision"]))
        if resp.status_code == 429:
            assert resp.headers.get("retry-after") == "30"
    assert seen[3] == (200, "warn", "allow")
    assert seen[5][0] == 429 and seen[5][1] == "throttle" and seen[5][2] == "throttle"
    assert seen[7][0] == 429 and seen[7][1] == "stop"
    message, _ = h.block_info(h.post_messages(h.messages_body(f"after stop {h.tag()}"), headers))
    assert "runaway agent loop" in message


def tool_turn(i: int) -> dict:
    return h.messages_conversation(
        [
            {"role": "user", "content": h.remember(f"keep trying {h.tag()}")},
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": f"toolu_{i}", "name": "Bash", "input": {"command": "npm test"}}
                ],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": f"toolu_{i}", "content": "1 failing"}],
            },
        ]
    )


def test_identical_tool_calls_stop_the_session(set_policy, original_policy):
    set_policy(small_limits(original_policy, max_requests_per_10_min=1000, max_identical_tool_calls=5))
    headers = session_headers()
    statuses = [h.post_messages(tool_turn(i), headers).status_code for i in range(5)]
    assert statuses[:4] == [200] * 4 and statuses[4] == 429
    message, _ = h.block_info(h.post_messages(tool_turn(9), headers))
    assert "same tool call repeated" in message or "runaway" in message


def test_redis_down_fails_open():
    h.compose("stop", "redis")
    try:
        states = []
        for _ in range(3):
            offset = h.audit_offset()
            resp = h.post_messages(h.messages_body(f"no redis {h.tag()}"), session_headers())
            assert resp.status_code == 200
            states.append((h.decision_row(resp, offset)["loop"] or {}).get("state"))
        assert "unavailable" in states or states == [None, None, None]
    finally:
        h.compose("start", "redis")
        time.sleep(1)
