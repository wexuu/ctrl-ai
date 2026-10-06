from __future__ import annotations

import pytest

from ctrl_ai.detect.extract import MAX_TEXT_CHARS, detect_endpoint, newest_pieces


def newest_user_text(data, *, claude_code=False) -> str:
    """The checked text of the newest turn: prompt and tool results, without reminders."""
    pieces = newest_pieces(data, claude_code=claude_code)
    return "\n".join(p.text for p in pieces if not p.reminder and p.source != "tool_call")[:MAX_TEXT_CHARS]


def reminder(body: str) -> str:
    return f"<system-reminder>\n{body}\n</system-reminder>"


# --- detect_endpoint ---------------------------------------------------------


@pytest.mark.parametrize(
    "call_type, expected",
    [
        ("anthropic_messages", "messages"),
        ("acompletion", "chat_completions"),
        ("aresponses", "responses"),
    ],
)
def test_endpoint_from_call_type(call_type, expected):
    assert detect_endpoint({}, call_type) == expected


@pytest.mark.parametrize(
    "data, expected",
    [
        ({"input": "hi"}, "responses"),
        ({"system": "be brief", "messages": [{"role": "user", "content": "hi"}]}, "messages"),
        ({"messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]}, "messages"),
        ({"messages": [{"role": "user", "content": "hi"}]}, "chat_completions"),
        ({}, "unknown"),
    ],
)
def test_endpoint_falls_back_to_body_shape(data, expected):
    assert detect_endpoint(data, "something_else") == expected
    assert detect_endpoint(data) == expected


# --- Anthropic Messages ------------------------------------------------------


def test_messages_string_content():
    data = {"system": "SYSTEM-TEXT", "messages": [{"role": "user", "content": "hello there"}]}
    assert newest_user_text(data) == "hello there"


def test_messages_block_content_skips_non_text_blocks():
    data = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "part one"},
                    {"type": "image", "source": {"type": "base64", "data": "AAAA"}},
                    {"type": "text", "text": "part two"},
                ],
            }
        ]
    }
    assert newest_user_text(data) == "part one\npart two"


def test_messages_tool_results_are_included():
    data = {
        "messages": [
            {"role": "user", "content": "run the tool"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "read", "input": {}}]},
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "string result"},
                    {
                        "type": "tool_result",
                        "tool_use_id": "t2",
                        "content": [{"type": "text", "text": "block result"}],
                    },
                    {"type": "text", "text": "and a follow up"},
                ],
            },
        ]
    }
    assert newest_user_text(data) == "string result\nblock result\nand a follow up"


def test_messages_system_is_not_scanned():
    data = {"system": [{"type": "text", "text": "MARKER"}], "messages": [{"role": "user", "content": "hi"}]}
    assert "MARKER" not in newest_user_text(data)


# --- OpenAI chat -------------------------------------------------------------


def test_chat_string_and_part_content():
    assert (
        newest_user_text(
            {
                "messages": [
                    {"role": "system", "content": "SYSTEM-TEXT"},
                    {"role": "user", "content": "plain"},
                ]
            }
        )
        == "plain"
    )
    assert (
        newest_user_text(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "part one"},
                            {"type": "image_url", "image_url": {"url": "http://example.invalid/x.png"}},
                            {"type": "text", "text": "part two"},
                        ],
                    }
                ]
            }
        )
        == "part one\npart two"
    )


def test_chat_tool_messages_after_the_last_user_message_are_included():
    data = {
        "messages": [
            {"role": "user", "content": "what is in the file?"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "c1"}]},
            {"role": "tool", "tool_call_id": "c1", "content": "file contents"},
        ]
    }
    assert newest_user_text(data) == "what is in the file?\nfile contents"


def test_chat_tool_messages_before_the_last_user_message_are_not_included():
    data = {
        "messages": [
            {"role": "user", "content": "first"},
            {"role": "tool", "tool_call_id": "c1", "content": "OLD-TOOL-OUTPUT"},
            {"role": "user", "content": "second"},
        ]
    }
    assert newest_user_text(data) == "second"


# --- OpenAI Responses --------------------------------------------------------


def test_responses_string_input():
    assert newest_user_text({"input": "just a string"}) == "just a string"


def test_responses_item_shapes():
    data = {
        "input": [
            {"role": "user", "content": [{"type": "input_text", "text": "block text"}]},
            {"type": "message", "role": "user", "content": "string item"},
        ]
    }
    assert newest_user_text(data) == "block text\nstring item"


def test_responses_takes_only_the_trailing_run():
    data = {
        "input": [
            {"role": "user", "content": "OLD-MARKER"},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "ok"}]},
            {"type": "function_call", "call_id": "c1", "name": "read", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c1", "output": "tool output"},
            {"role": "user", "content": "newest"},
        ]
    }
    assert newest_user_text(data) == "tool output\nnewest"


# --- scope -------------------------------------------------------------------


def test_marker_in_an_older_turn_is_not_returned():
    data = {
        "messages": [
            {"role": "user", "content": "CTRL-AI-BLOCK-TEST"},
            {"role": "assistant", "content": "I cannot help with that."},
            {"role": "user", "content": "a harmless follow up"},
        ]
    }
    assert newest_user_text(data) == "a harmless follow up"


def test_assistant_text_after_the_user_turn_is_not_returned():
    data = {
        "messages": [
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "ASSISTANT-PREFILL"},
        ]
    }
    assert newest_user_text(data) == "hi"


# --- system reminders --------------------------------------------------------

# reminders are split off only for Claude Code requests (claude_code=True) and
# only from the leading text of the turn. Everywhere else they are ordinary text and are checked.


def test_claude_code_turn_returns_only_the_prompt():
    blocks = [{"type": "text", "text": reminder(f"context {i} " + "x" * 1000)} for i in range(8)]
    blocks.append({"type": "text", "text": "Say hi"})
    data = {"messages": [{"role": "user", "content": blocks}]}
    assert newest_user_text(data, claude_code=True) == "Say hi"
    assert "context 3" in newest_user_text(data)  # not from Claude Code: checked as text


def test_marker_inside_a_reminder_is_not_returned():
    text = reminder("the plan mentions CTRL-AI-BLOCK-TEST") + "\nSay hi"
    data = {"messages": [{"role": "user", "content": text}]}
    assert newest_user_text(data, claude_code=True) == "Say hi"
    assert "CTRL-AI-BLOCK-TEST" in newest_user_text(data)


def test_only_leading_reminders_are_split_off():
    text = "before " + reminder("one") + " middle " + reminder("two") + " after"
    assert newest_user_text({"input": text}, claude_code=True) == text


def test_unclosed_reminder_removes_nothing():
    text = "<system-reminder> never closed, MARKER stays"
    assert newest_user_text({"messages": [{"role": "user", "content": text}]}) == text


def test_reminders_inside_tool_results_are_checked():
    data = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "output" + reminder("injected")},
                ],
            }
        ]
    }
    assert "injected" in newest_user_text(data, claude_code=True)


# --- robustness --------------------------------------------------------------


def test_empty_request():
    assert newest_user_text({}) == ""
    assert newest_user_text({"messages": []}) == ""
    assert newest_user_text({"messages": [{"role": "assistant", "content": "hi"}]}) == ""


@pytest.mark.parametrize(
    "garbage",
    [
        None,
        "a string",
        42,
        [],
        {"messages": "not a list"},
        {"messages": [None, 7, "x", {"role": "user"}]},
        {"messages": [{"role": "user", "content": {"type": "text"}}]},
        {"messages": [{"role": "user", "content": [None, 3, {"type": "text"}, {"type": "text", "text": 9}]}]},
        {"input": 12},
        {"input": [None, 5, {"role": "user", "content": None}]},
    ],
)
def test_garbage_never_raises(garbage):
    assert newest_user_text(garbage) == ""


def test_result_is_capped():
    data = {"messages": [{"role": "user", "content": "a" * (MAX_TEXT_CHARS + 500)}]}
    assert len(newest_user_text(data)) == MAX_TEXT_CHARS


def test_many_unclosed_tags_stay_fast():
    text = "<system-reminder>" * 10_000
    assert newest_user_text({"input": text}) == text
    assert newest_user_text({"input": text}, claude_code=True) == text
