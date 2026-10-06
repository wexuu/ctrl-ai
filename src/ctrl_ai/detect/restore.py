"""Put the real values back into the model's answer. Duck-typed, no LiteLLM import.

Response shapes per endpoint (spike Q5): a plain ``dict`` (Anthropic JSON) for
``/v1/messages``, ``ModelResponse`` for chat completions, ``ResponsesAPIResponse`` for
``/v1/responses``. Streams: only chat completions are restored (``ModelResponseStream``
chunks); ``/v1/messages`` (raw SSE bytes) and ``/v1/responses`` streams pass through.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from ctrl_ai.detect.masking import StreamRestorer, restore_text, restore_value


def _get(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def _set(obj: Any, name: str, value: Any) -> None:
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)


def restore_response(response: Any, mapping: dict[str, str]) -> Any:
    """Restore in place where possible; returns the (same) response."""
    if not mapping or response is None:
        return response
    if isinstance(response, dict) and "content" in response:  # Anthropic Messages
        response["content"] = restore_value(response["content"], mapping)
        return response
    choices = _get(response, "choices")
    if choices:  # chat completions
        for choice in choices:
            message = _get(choice, "message")
            if message is None:
                continue
            content = _get(message, "content")
            if isinstance(content, str):
                _set(message, "content", restore_text(content, mapping))
            for call in _get(message, "tool_calls") or []:
                function = _get(call, "function")
                args = _get(function, "arguments") if function is not None else None
                if isinstance(args, str):
                    _set(function, "arguments", restore_value(args, mapping, "arguments"))
        return response
    output = _get(response, "output")
    if output:  # Responses API
        for item in output:
            kind = _get(item, "type")
            if kind == "message":
                for part in _get(item, "content") or []:
                    text = _get(part, "text")
                    if isinstance(text, str):
                        _set(part, "text", restore_text(text, mapping))
            elif kind == "function_call":
                args = _get(item, "arguments")
                if isinstance(args, str):
                    _set(item, "arguments", restore_value(args, mapping, "arguments"))
    return response


async def restore_chat_stream(chunks: AsyncIterator[Any], mapping: dict[str, str]) -> AsyncIterator[Any]:
    """Chat-completions stream: restore surrogates even when split across chunks."""
    restorer = StreamRestorer(mapping)
    last = None
    async for chunk in chunks:
        last = chunk
        choices = _get(chunk, "choices") or []
        delta = _get(choices[0], "delta") if choices else None
        content = _get(delta, "content") if delta is not None else None
        finished = bool(choices and _get(choices[0], "finish_reason"))
        if isinstance(content, str):
            text = restorer.feed(content)
            if finished:
                text += restorer.flush()
            _set(delta, "content", text)
        elif finished and restorer.pending and delta is not None:
            _set(delta, "content", restorer.flush())
        yield chunk
    if restorer.pending and last is not None:
        tail = last.model_copy(deep=True) if hasattr(last, "model_copy") else None
        choices = _get(tail, "choices") if tail is not None else None
        if choices:
            delta = _get(choices[0], "delta")
            if delta is not None:
                _set(delta, "content", restorer.flush())
                _set(choices[0], "finish_reason", None)
                yield tail
