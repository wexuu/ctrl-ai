"""Find the newest turn in a request body, as LiteLLM hands it to a hook.

Only the newest user turn is returned. Clients resend the whole conversation
on every request, so scanning older turns would let one blocked prompt block
the rest of the session.

The turn comes back as pieces with their source:
  prompt       text the user wrote in the newest user turn
  tool_result  tool output that arrives with it (untrusted input)
  tool_call    the arguments of the tool calls those results answer, as compact JSON
System prompts are never extracted (trusted operator context).

Claude Code's ``<system-reminder>`` blocks are split off as ``reminder`` pieces
only when the request comes from Claude Code and only from the leading text of the
turn, where Claude Code puts them. Anywhere else the tags are ordinary text.
"""

from __future__ import annotations

import json
from typing import Any

from ctrl_ai.core.context import Piece

MAX_TEXT_CHARS = 200_000

_CALL_TYPE_ENDPOINTS = {
    "anthropic_messages": "messages",
    "acompletion": "chat_completions",
    "aresponses": "responses",
}
_TEXT_BLOCK_TYPES = ("text", "input_text")
_REMINDER_OPEN = "<system-reminder>"
_REMINDER_CLOSE = "</system-reminder>"


def detect_endpoint(data: dict, call_type: str | None = None) -> str:
    """Return ``messages``, ``chat_completions``, ``responses`` or ``unknown``.

    The call type LiteLLM passes to the hook decides; the shape of the body is
    only a fallback for call types we do not know.
    """
    known = _CALL_TYPE_ENDPOINTS.get(str(getattr(call_type, "value", call_type)))
    if known:
        return known
    if not isinstance(data, dict):
        return "unknown"
    if "input" in data:
        return "responses"
    if "system" in data or _has_block_content(data.get("messages")):
        return "messages"
    if "messages" in data:
        return "chat_completions"
    return "unknown"


def is_claude_code(data: dict) -> bool:
    """True when the request comes from Claude Code.

    Reads only the ``user-agent`` and ``x-app`` header values, nothing else.
    """
    try:
        headers = (data.get("proxy_server_request") or {}).get("headers") or {}
        agent = _header(headers, "user-agent") or ""
        return agent.startswith("claude-cli/") or _header(headers, "x-app") == "cli"
    except Exception:
        return False


def _header(headers: Any, name: str) -> str | None:
    if not isinstance(headers, dict):
        return None
    value = headers.get(name)
    if value is None:
        for key in headers:
            if isinstance(key, str) and key.lower() == name:
                value = headers[key]
                break
    return value if isinstance(value, str) else None


def newest_pieces(data: dict, *, claude_code: bool = False) -> list[Piece]:
    """The newest turn as pieces with their source. Never raises."""
    try:
        raw = _newest_turn_sourced(data)
        out: list[Piece] = []
        leading = claude_code
        for text, source in raw:
            if source == "prompt" and leading:
                reminders, rest = _split_leading_reminders(text)
                out.extend(Piece(r[:MAX_TEXT_CHARS], "prompt", reminder=True) for r in reminders if r.strip())
                if rest.strip():
                    leading = False
                    out.append(Piece(rest.strip()[:MAX_TEXT_CHARS], source))
                continue
            stripped = text.strip()
            if stripped:
                out.append(Piece(stripped[:MAX_TEXT_CHARS], source))
        return out
    except Exception:
        return []


def _split_leading_reminders(text: str) -> tuple[list[str], str]:
    """Cut ``<system-reminder>…</system-reminder>`` spans off the start of ``text``.

    Uses ``str.find`` so that many unclosed tags cannot make it quadratic. An
    unclosed opening tag ends the leading run.
    """
    reminders: list[str] = []
    pos = 0
    while True:
        start = len(text) - len(text[pos:].lstrip())
        if not text.startswith(_REMINDER_OPEN, start):
            break
        end = text.find(_REMINDER_CLOSE, start + len(_REMINDER_OPEN))
        if end < 0:
            break
        reminders.append(text[start + len(_REMINDER_OPEN) : end])
        pos = end + len(_REMINDER_CLOSE)
    return reminders, text[pos:]


def _newest_turn_sourced(data: dict) -> list[tuple[str, str]]:
    messages = data.get("messages")
    if isinstance(messages, list):
        return _from_messages(messages)
    return _from_input(data.get("input"))


def _from_messages(messages: list) -> list[tuple[str, str]]:
    """Anthropic Messages and OpenAI chat: the last user message and what answers tools.

    OpenAI chat carries tool output in separate ``role: tool`` messages, so any of
    those after the last user message belong to the same turn, and the assistant
    tool calls they answer are checked as ``tool_call``.
    """
    last = max((i for i, msg in enumerate(messages) if _role(msg) == "user"), default=None)
    if last is None:
        return []
    user = messages[last]
    out = _sourced_content(user.get("content"))
    has_results = any(src == "tool_result" for _, src in out)
    if has_results and last > 0 and _role(messages[last - 1]) == "assistant":
        out = _tool_calls(messages[last - 1]) + out
    tail = messages[last + 1 :]
    tool_msgs = [m for m in tail if _role(m) == "tool"]
    if tool_msgs:
        for msg in tail:
            if _role(msg) == "assistant":
                calls = _tool_calls(msg)
                if calls:
                    out.extend(calls)
        for msg in tool_msgs:
            out.extend((t, "tool_result") for t in _content_texts(msg.get("content")))
    return out


def _tool_calls(message: dict) -> list[tuple[str, str]]:
    """Tool-call arguments of an assistant message: Messages ``tool_use`` or chat ``tool_calls``."""
    out = []
    content = message.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                out.append((_compact_json(block.get("input")), "tool_call"))
    for call in message.get("tool_calls") or []:
        if isinstance(call, dict):
            fn = call.get("function") or {}
            out.append((_compact_args(fn.get("arguments")), "tool_call"))
    return [(t, s) for t, s in out if t]


def _compact_args(args: Any) -> str:
    if isinstance(args, str):
        try:
            return _compact_json(json.loads(args))
        except ValueError:
            return args
    return _compact_json(args)


def _compact_json(value: Any) -> str:
    if value is None:
        return ""
    try:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _from_input(value: Any) -> list[tuple[str, str]]:
    """OpenAI Responses: a string, or the trailing run of user items, tool calls and outputs."""
    if isinstance(value, str):
        return [(value, "prompt")]
    if not isinstance(value, list):
        return []
    run: list[list[tuple[str, str]]] = []
    for item in reversed(value):
        texts = _input_item_texts(item)
        if texts is None:
            break
        run.append(texts)
    return [pair for pairs in reversed(run) for pair in pairs]


def _input_item_texts(item: Any) -> list[tuple[str, str]] | None:
    """Sourced texts of one Responses input item, or None if it is not new input."""
    if isinstance(item, str):
        return [(item, "prompt")]
    if not isinstance(item, dict):
        return None
    kind = item.get("type")
    if kind == "function_call_output":
        return [(t, "tool_result") for t in _content_texts(item.get("output"))]
    if kind == "function_call":
        args = _compact_args(item.get("arguments"))
        return [(args, "tool_call")] if args else []
    if item.get("role") == "user" and item.get("type", "message") == "message":
        return _sourced_content(item.get("content"))
    return None


def _sourced_content(content: Any) -> list[tuple[str, str]]:
    if isinstance(content, str):
        return [(content, "prompt")]
    out: list[tuple[str, str]] = []
    if isinstance(content, list):
        for block in content:
            if isinstance(block, str):
                out.append((block, "prompt"))
            elif not isinstance(block, dict):
                continue
            elif block.get("type") in _TEXT_BLOCK_TYPES and isinstance(block.get("text"), str):
                out.append((block["text"], "prompt"))
            elif block.get("type") == "tool_result":
                out.extend(
                    (t, "tool_result") for t in _content_texts(block.get("content"), tool_results=False)
                )
    return out


def _content_texts(content: Any, tool_results: bool = True) -> list[str]:
    """Texts in a content value: a string, or a list of text and tool-result blocks."""
    if isinstance(content, str):
        return [content]
    pieces: list[str] = []
    if isinstance(content, list):
        for block in content:
            if isinstance(block, str):
                pieces.append(block)
            elif not isinstance(block, dict):
                continue
            elif block.get("type") in (*_TEXT_BLOCK_TYPES, "output_text") and isinstance(
                block.get("text"), str
            ):
                pieces.append(block["text"])
            elif tool_results and block.get("type") == "tool_result":
                # One level only: a tool result holds text blocks, not further results.
                pieces.extend(_content_texts(block.get("content"), tool_results=False))
    return pieces


def _role(message: Any) -> Any:
    return message.get("role") if isinstance(message, dict) else None


def _has_block_content(messages: Any) -> bool:
    if not isinstance(messages, list):
        return False
    return any(isinstance(msg, dict) and isinstance(msg.get("content"), list) for msg in messages)


# ------------------------------------------------------------ loop-cap inputs


def session_header(data: dict) -> str | None:
    """Claude Code's session id: the ``x-claude-code-session-id`` header value only."""
    try:
        headers = (data.get("proxy_server_request") or {}).get("headers") or {}
        value = _header(headers, "x-claude-code-session-id")
        return value[:200] if value else None
    except Exception:
        return None


def latest_prompt_text(data: dict) -> str:
    """The text of the newest user message that the user wrote (not only tool results).

    In an agent loop every tool round is a new user message with tool results; they all
    belong to the same user turn, which is identified by the last real prompt.
    """
    try:
        messages = data.get("messages")
        if isinstance(messages, list):
            for msg in reversed(messages):
                if _role(msg) == "user":
                    texts = [t for t, src in _sourced_content(msg.get("content")) if src == "prompt"]
                    if any(t.strip() for t in texts):
                        return "\n".join(texts)
            return ""
        value = data.get("input")
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            for item in reversed(value):
                if isinstance(item, str):
                    return item
                if isinstance(item, dict) and item.get("role") == "user":
                    texts = [t for t, src in _sourced_content(item.get("content")) if src == "prompt"]
                    if texts:
                        return "\n".join(texts)
    except Exception:
        pass
    return ""


def tool_call_signature(data: dict) -> str | None:
    """Name and normalised arguments of the newest assistant tool call(s), or None."""
    try:
        messages = data.get("messages")
        if isinstance(messages, list):
            for msg in reversed(messages):
                if _role(msg) != "assistant":
                    continue
                calls = []
                content = msg.get("content")
                if isinstance(content, list):
                    calls += [
                        (b.get("name"), _compact_json(b.get("input")))
                        for b in content
                        if isinstance(b, dict) and b.get("type") == "tool_use"
                    ]
                calls += [
                    (
                        (c.get("function") or {}).get("name"),
                        _compact_args((c.get("function") or {}).get("arguments")),
                    )
                    for c in msg.get("tool_calls") or []
                    if isinstance(c, dict)
                ]
                return json.dumps(calls, sort_keys=True) if calls else None
            return None
        value = data.get("input")
        if isinstance(value, list):
            calls = [
                (i.get("name"), _compact_args(i.get("arguments")))
                for i in value
                if isinstance(i, dict) and i.get("type") == "function_call"
            ]
            if calls:
                return json.dumps(calls[-1:], sort_keys=True)
    except Exception:
        pass
    return None
