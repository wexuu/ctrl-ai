"""Helpers for the admin panel's end-to-end tests: an admin client for the test stack's UI."""

from __future__ import annotations

import os
import time

import httpx
import pytest

UI_URL = os.environ.get("CTRL_AI_TEST_UI_URL", "http://localhost:4100").rstrip("/")


class Admin:
    """An admin client (no sign-in) that sends the CSRF header on every POST."""

    def __init__(self):
        self.client = httpx.Client(base_url=UI_URL, timeout=30)
        resp = self.client.get("/api/auth/session")
        assert resp.status_code == 200, resp.text
        self.csrf = resp.json()["csrf"]

    def get(self, path: str, **kw) -> httpx.Response:
        return self.client.get(path, **kw)

    def post(self, path: str, body: dict | None = None, *, csrf: bool = True) -> httpx.Response:
        headers = {"x-ctrl-ai-csrf": self.csrf} if csrf else {}
        return self.client.post(path, json=body or {}, headers=headers)

    def config(self, name: str) -> dict:
        resp = self.get(f"/api/admin/config/{name}")
        assert resp.status_code == 200, resp.text
        return resp.json()

    def save(
        self, name: str, doc: dict, reason: str = "e2e test", expected: str | None = None
    ) -> httpx.Response:
        if expected is None:
            expected = self.config(name)["version"]
        return self.post(
            f"/api/admin/config/{name}", {"doc": doc, "expected_version": expected, "reason": reason}
        )


def wait_ui(timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(UI_URL + "/api/health", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    pytest.fail(f"The UI at {UI_URL} is not answering. Run `make test-up`.")
