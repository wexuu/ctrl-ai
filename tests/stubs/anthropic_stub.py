"""Stub of the Anthropic Messages API for keyless tests (standard library only).

Routes:
  POST   /v1/messages     non-streaming JSON, or server-sent events when body.stream is true
  GET    /_stub/health    200 {"ok": true}
  GET    /_stub/requests  what was received since the last reset (no credential values)
  DELETE /_stub/requests  reset that list

Newest user text containing UPSTREAM-400-TEST gets an HTTP 400 with an Anthropic error body.
A 400 rather than a 500, because LiteLLM retries a 500 twice and that takes about five seconds.

Semantic-check and fallback markers:
  AI judge calls (system prompt contains CTRL-AI-JUDGE) are answered with the judge's JSON:
    attack 0.91 when the text contains ATTACKTEST or JUDGE-HIGH-TEST, else 0.05;
    JUDGE-DOWN-TEST → HTTP 500; JUDGE-SLOW-TEST → sleeps JUDGE_SLOW_SECONDS first.
  PROVIDER-DOWN-TEST with model claude-opus-5-5 → HTTP 500 (the fallback chain takes over).
  SLOW-1S-TEST → the answer comes after one second (latency of the parallel semantic check).
  The request log records whether the synthetic IBAN / PESEL arrived (booleans, never the text).
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "9001"))
REPLY_PREFIX = "stub-reply: "
INPUT_TOKENS = 25
OUTPUT_TOKENS = 12
UPSTREAM_400_MARKER = "UPSTREAM-400-TEST"
JUDGE_MARKER = "CTRL-AI-JUDGE"
JUDGE_SLOW_SECONDS = 7
SYNTHETIC_IBANS = ("PL61 1090 1014 0000 0712 1981 2874", "PL61109010140000071219812874")
SYNTHETIC_PESEL = "44051401359"

LOG: list[dict] = []
LOCK = threading.Lock()


def newest_user_text(body: dict) -> str:
    """Text of the newest user turn: string content, or its text blocks joined."""
    for msg in reversed(body.get("messages") or []):
        if not isinstance(msg, dict) or msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = [
                b.get("text", "")
                for b in content
                if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
            ]
            return "\n".join(parts)
        return ""
    return ""


def system_text(body: dict) -> str:
    system = body.get("system")
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        return " ".join(b.get("text", "") for b in system if isinstance(b, dict))
    return ""


def all_text(body: dict) -> str:
    """Every string the model would see, for the synthetic-data booleans."""
    return json.dumps(body.get("messages") or [], ensure_ascii=False) + system_text(body)


def credential_summary(value: str | None, *, check_oauth: bool) -> dict:
    """Presence and length of a credential header. Never the value itself."""
    if value is None:
        return {"present": False, "length": 0} | ({"oauth_shaped": False} if check_oauth else {})
    out = {"present": True, "length": len(value)}
    if check_oauth:
        out["oauth_shaped"] = value.startswith("Bearer sk-ant-oat")
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # the default access log prints the path only; keep stdout quiet
        pass

    # ------------------------------------------------------------ helpers
    def _route(self) -> str:
        return self.path.split("?", 1)[0]

    def _read_json(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    def _json(self, status: int, obj) -> None:
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.send_header("request-id", "req_stub_" + uuid.uuid4().hex[:16])
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: int, etype: str, message: str) -> None:
        self._json(status, {"type": "error", "error": {"type": etype, "message": message}})

    def _record(self, body, status: int) -> None:
        body = body if isinstance(body, dict) else {}
        entry = {
            "ts": time.time(),
            "method": self.command,
            "path": self.path,
            "header_names": sorted({k.lower() for k in self.headers}),
            "anthropic_beta": self.headers.get("anthropic-beta"),
            "anthropic_version": self.headers.get("anthropic-version"),
            "authorization": credential_summary(self.headers.get("authorization"), check_oauth=True),
            "x_api_key": credential_summary(self.headers.get("x-api-key"), check_oauth=False),
            "model": body.get("model"),
            "stream": bool(body.get("stream")),
            "user_text_length": len(newest_user_text(body)),
            "judge": JUDGE_MARKER in system_text(body),
            "saw_synthetic_iban": any(v in all_text(body) for v in SYNTHETIC_IBANS),
            "saw_synthetic_pesel": SYNTHETIC_PESEL in all_text(body),
            "status": status,
        }
        with LOCK:
            LOG.append(entry)
        print("STUB-ANTHROPIC " + json.dumps(entry), flush=True)

    # --------------------------------------------------------------- routes
    def do_GET(self):
        route = self._route()
        if route == "/_stub/health":
            return self._json(200, {"ok": True})
        if route == "/_stub/requests":
            with LOCK:
                return self._json(200, list(LOG))
        return self._error(404, "not_found_error", f"stub: no route GET {route}")

    def do_DELETE(self):
        if self._route() == "/_stub/requests":
            with LOCK:
                LOG.clear()
            return self._json(200, {"ok": True})
        return self._error(404, "not_found_error", "stub: no such route")

    def do_POST(self):
        route = self._route()
        body = self._read_json()
        if route != "/v1/messages":
            self._record(body, 404)
            return self._error(404, "not_found_error", f"stub: no route POST {route}")
        if not isinstance(body, dict) or not body.get("model") or not body.get("messages"):
            self._record(body, 400)
            return self._error(400, "invalid_request_error", "stub: model and messages are required")
        text = newest_user_text(body)
        if JUDGE_MARKER in system_text(body):
            return self._judge(body, text)
        if "PROVIDER-DOWN-TEST" in text and body.get("model") == "claude-opus-5-5":
            self._record(body, 500)
            return self._error(500, "api_error", "stub: provider down")
        if "SLOW-1S-TEST" in text:
            time.sleep(1.0)
        if UPSTREAM_400_MARKER in text:
            self._record(body, 400)
            return self._error(400, "invalid_request_error", "stub: forced upstream 400")
        self._record(body, 200)
        reply = REPLY_PREFIX + text[:40]
        msg_id = "msg_stub_" + uuid.uuid4().hex[:20]
        if body.get("stream"):
            return self._stream(body["model"], msg_id, reply)
        return self._json(
            200,
            {
                "id": msg_id,
                "type": "message",
                "role": "assistant",
                "model": body["model"],
                "content": [{"type": "text", "text": reply}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {
                    "input_tokens": INPUT_TOKENS,
                    "output_tokens": OUTPUT_TOKENS,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0,
                },
            },
        )

    def _judge(self, body: dict, text: str) -> None:
        if "JUDGE-DOWN-TEST" in text:
            self._record(body, 500)
            return self._error(500, "api_error", "stub: judge down")
        if "JUDGE-SLOW-TEST" in text:
            time.sleep(JUDGE_SLOW_SECONDS)
        self._record(body, 200)
        score = 0.91 if ("ATTACKTEST" in text or "JUDGE-HIGH-TEST" in text) else 0.05
        answer = json.dumps(
            {
                "attack": score,
                "category": "instruction_override" if score > 0.5 else "none",
                "reason": "stub judge",
            }
        )
        return self._json(
            200,
            {
                "id": "msg_stub_judge_" + uuid.uuid4().hex[:12],
                "type": "message",
                "role": "assistant",
                "model": body["model"],
                "content": [{"type": "text", "text": answer}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {
                    "input_tokens": 120,
                    "output_tokens": 30,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0,
                },
            },
        )

    def _stream(self, model: str, msg_id: str, reply: str) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("transfer-encoding", "chunked")
        self.send_header("request-id", "req_stub_" + uuid.uuid4().hex[:16])
        self.end_headers()

        def emit(event: str, data: dict) -> None:
            chunk = f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()
            self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.flush()

        emit(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": msg_id,
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {
                        "input_tokens": INPUT_TOKENS,
                        "output_tokens": 1,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                    },
                },
            },
        )
        emit(
            "content_block_start",
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        )
        emit("ping", {"type": "ping"})
        third = max(1, len(reply) // 3)
        for piece in (reply[:third], reply[third : 2 * third], reply[2 * third :]):
            emit(
                "content_block_delta",
                {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": piece}},
            )
            time.sleep(0.02)
        emit("content_block_stop", {"type": "content_block_stop", "index": 0})
        emit(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": OUTPUT_TOKENS},
            },
        )
        emit("message_stop", {"type": "message_stop"})
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


if __name__ == "__main__":
    print(f"stub-anthropic listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
