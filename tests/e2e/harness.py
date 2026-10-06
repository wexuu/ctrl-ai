"""Helpers for the end-to-end tests: endpoints, request builders, stub logs and the audit file.

Everything here drives the gateway the way a client would. Nothing reads gateway internals.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import uuid
from collections.abc import Callable
from pathlib import Path

import httpx

from tests.e2e.constants import MODEL

REPO = Path(__file__).resolve().parents[2]

BASE_URL = os.environ.get("CTRL_AI_TEST_BASE_URL", "http://localhost:4000").rstrip("/")
STUB_ANTHROPIC_URL = os.environ.get("CTRL_AI_TEST_STUB_ANTHROPIC_URL", "http://localhost:9001").rstrip("/")
STUB_JEV_URL = os.environ.get("CTRL_AI_TEST_STUB_JEV_URL", "http://localhost:9002").rstrip("/")
TEST_KEY = os.environ.get("CTRL_AI_TEST_KEY", "sk-ctrl-ai-test-master")
RUNTIME = Path(os.environ.get("CTRL_AI_TEST_RUNTIME", REPO / "tests" / "e2e" / "runtime"))
AUDIT_FILE = RUNTIME / "audit.jsonl"
POLICY_FILE = RUNTIME / "policy.yaml"

TIMEOUT = httpx.Timeout(30.0, connect=5.0)

# Every prompt the suite sends is remembered here, so T99 can prove none reached the audit log.
PROMPTS_SENT: set[str] = set()


def tag() -> str:
    """A short unique token, so prompts differ between tests and can be searched for later."""
    return "e2e-prompt-" + uuid.uuid4().hex[:10]


def remember(text: str) -> str:
    PROMPTS_SENT.add(text)
    return text


# ---------------------------------------------------------------- request bodies


def messages_body(text: str, *, stream: bool = False, model: str = MODEL, max_tokens: int = 64) -> dict:
    """Anthropic Messages body with one user turn of text blocks."""
    remember(text)
    return {
        "model": model,
        "max_tokens": max_tokens,
        "stream": stream,
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    }


def messages_conversation(
    messages: list[dict], *, stream: bool = False, model: str = MODEL, max_tokens: int = 64
) -> dict:
    """Anthropic Messages body with a given list of turns. The caller remembers its own texts."""
    return {"model": model, "max_tokens": max_tokens, "stream": stream, "messages": messages}


def chat_body(text: str, *, stream: bool = False, model: str = MODEL, max_tokens: int = 64) -> dict:
    """OpenAI chat body. max_tokens is always sent; without it LiteLLM asks upstream for 128,000."""
    remember(text)
    return {
        "model": model,
        "max_tokens": max_tokens,
        "stream": stream,
        "messages": [{"role": "user", "content": text}],
    }


# ---------------------------------------------------------------- headers


def bearer_headers(key: str | None = TEST_KEY) -> dict:
    h = {"anthropic-version": "2023-06-01", "content-type": "application/json"}
    if key is not None:
        h["authorization"] = f"Bearer {key}"
    return h


# ---------------------------------------------------------------- gateway calls


def post(path: str, body: dict, headers: dict | None = None) -> httpx.Response:
    """POST to the gateway and read the whole response."""
    with httpx.Client(timeout=TIMEOUT) as c:
        return c.post(BASE_URL + path, json=body, headers=bearer_headers() if headers is None else headers)


def post_messages(body: dict, headers: dict | None = None) -> httpx.Response:
    return post("/v1/messages", body, headers)


def post_chat(body: dict, headers: dict | None = None) -> httpx.Response:
    return post("/v1/chat/completions", body, headers)


def stream_events(path: str, body: dict, headers: dict | None = None) -> tuple[int, str, list[str], str]:
    """POST a streaming request; return status, content type, the SSE event types in order, and the raw text."""
    events: list[str] = []
    chunks: list[str] = []
    with (
        httpx.Client(timeout=TIMEOUT) as c,
        c.stream(
            "POST", BASE_URL + path, json=body, headers=bearer_headers() if headers is None else headers
        ) as r,
    ):
        for line in r.iter_lines():
            chunks.append(line)
            if line.startswith("event:"):
                events.append(line[len("event:") :].strip())
        return r.status_code, r.headers.get("content-type", ""), events, "\n".join(chunks)


def call_id(resp: httpx.Response) -> str | None:
    """LiteLLM's call id for a response, which the audit rows carry as request_id."""
    return resp.headers.get("x-litellm-call-id")


def block_info(resp: httpx.Response) -> tuple[str, str | None]:
    """The block message and rule id from a block response, on either endpoint."""
    err = resp.json().get("error") or {}
    return err.get("message") or "", (err.get("provider_specific_fields") or {}).get("rule")


# ---------------------------------------------------------------- stubs


def stub_requests(stub_url: str) -> list[dict]:
    r = httpx.get(stub_url + "/_stub/requests", timeout=5)
    r.raise_for_status()
    return r.json()


def anthropic_requests() -> list[dict]:
    """Requests the stub Anthropic server received, excluding its own health checks."""
    return [e for e in stub_requests(STUB_ANTHROPIC_URL) if e.get("path", "").startswith("/v1/")]


def jev_requests() -> list[dict]:
    return [e for e in stub_requests(STUB_JEV_URL) if e.get("path", "").startswith("/v1/")]


def compose(*args: str) -> None:
    """Run a docker compose command against the test stack (stop/start a service)."""
    project = os.environ.get("CTRL_AI_TEST_PROJECT", "ctrl-ai-test")
    subprocess.run(
        [
            "docker",
            "compose",
            "--project-directory",
            str(REPO),
            "-f",
            "deploy/docker/compose.yml",
            "-f",
            "deploy/docker/compose.test.yml",
            "--env-file",
            "tests/e2e/test.env",
            "-p",
            project,
            *args,
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )


def reset_stubs() -> None:
    for url in (STUB_ANTHROPIC_URL, STUB_JEV_URL):
        httpx.delete(url + "/_stub/requests", timeout=5).raise_for_status()


# ---------------------------------------------------------------- audit log


def audit_offset() -> int:
    """Current end of the audit file. Rows appended later are read from here."""
    try:
        return AUDIT_FILE.stat().st_size
    except FileNotFoundError:
        return 0


def audit_rows_since(offset: int) -> list[dict]:
    """Rows appended after `offset`. The file is never truncated or rewritten during a session."""
    try:
        with AUDIT_FILE.open("rb") as f:
            f.seek(offset)
            data = f.read()
    except FileNotFoundError:
        return []
    rows = []
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue  # a row still being written; the next poll sees it whole
    return rows


def wait_for_row(predicate: Callable[[dict], bool], offset: int, timeout: float = 5.0) -> dict:
    """Poll until a row after `offset` matches. The usage row is written after the response returns."""
    deadline = time.monotonic() + timeout
    while True:
        for row in audit_rows_since(offset):
            if predicate(row):
                return row
        if time.monotonic() >= deadline:
            types = [r.get("type") for r in audit_rows_since(offset)]
            raise AssertionError(f"no matching audit row within {timeout}s; rows since offset: {types}")
        time.sleep(0.1)


def _row_for(row_type: str, resp: httpx.Response, offset: int, timeout: float) -> dict:
    """The row of `row_type` for this response, matched on request_id = x-litellm-call-id.

    If the response carries no call id, or no row carries it, fall back to the only row of that
    type since `offset`. Each test sends one request at a time, so that row is unambiguous.
    """
    cid = call_id(resp)
    deadline = time.monotonic() + timeout
    while True:
        rows = [r for r in audit_rows_since(offset) if r.get("type") == row_type]
        if cid:
            for r in rows:
                if r.get("request_id") == cid:
                    return r
        if time.monotonic() >= deadline:
            if len(rows) == 1:
                return rows[0]
            raise AssertionError(
                f"no {row_type} row for call id {cid!r} within {timeout}s "
                f"({len(rows)} {row_type} rows since offset)"
            )
        time.sleep(0.1)


def decision_row(resp: httpx.Response, offset: int, timeout: float = 5.0) -> dict:
    return _row_for("decision", resp, offset, timeout)


def usage_row(resp: httpx.Response, offset: int, timeout: float = 5.0) -> dict:
    return _row_for("usage", resp, offset, timeout)


# ---------------------------------------------------------------- policy


def policy_version(text: str) -> str:
    """The policy version: the first 8 hex characters of the SHA-256 of the policy file."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def write_policy(text: str) -> None:
    """Write the policy in place and make sure the gateway sees a change.

    The guardrail re-reads the file when its mtime or size changes. A write within the same
    mtime tick and of the same size would go unnoticed, so the mtime is always moved forward
    by at least two seconds.
    """
    before = POLICY_FILE.stat().st_mtime if POLICY_FILE.exists() else 0.0
    with POLICY_FILE.open("w", encoding="utf-8") as f:  # in place, keeping the host-owned inode
        f.write(text)
    mtime = max(time.time(), before + 2.0)
    os.utime(POLICY_FILE, (mtime, mtime))
