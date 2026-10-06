"""Fixtures for the end-to-end tests. Run `make test-up` first; see tests/e2e/harness.py."""

from __future__ import annotations

import time

import httpx
import pytest

from tests.e2e import admin_client, harness, stack_config


def _answers(url: str) -> bool:
    try:
        return httpx.get(url, timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.fixture(scope="session")
def stack():
    """Wait for the gateway and both stubs; fail clearly if the test stack is not running."""
    targets = {
        "gateway": harness.BASE_URL + "/health/liveliness",
        "stub-anthropic": harness.STUB_ANTHROPIC_URL + "/_stub/health",
        "stub-jev": harness.STUB_JEV_URL + "/_stub/health",
    }
    deadline = time.monotonic() + 30
    missing = list(targets)
    while missing and time.monotonic() < deadline:
        missing = [name for name, url in targets.items() if not _answers(url)]
        if missing:
            time.sleep(1)
    if missing:
        pytest.exit(f"Not answering: {', '.join(missing)}. Run `make test-up` first.", returncode=2)
    if not harness.AUDIT_FILE.exists() or not harness.POLICY_FILE.exists():
        pytest.exit(f"{harness.RUNTIME} is not prepared. Run `make test-up` first.", returncode=2)
    return targets


@pytest.fixture(autouse=True)
def clean_stubs(request):
    """Reset both stubs' request logs before every test, except live tests (no stubs there)."""
    if request.node.get_closest_marker("live"):
        yield
        return
    request.getfixturevalue("stack")
    harness.reset_stubs()
    yield


@pytest.fixture
def audit_start():
    """The audit file offset before the test's requests."""
    return harness.audit_offset()


@pytest.fixture
def set_policy():
    """Write a policy for one test and restore the original afterwards, both noticed by the gateway."""
    original = harness.POLICY_FILE.read_text(encoding="utf-8")
    changed = False

    def _set(text: str) -> None:
        nonlocal changed
        changed = True
        harness.write_policy(text)

    yield _set
    if changed:
        harness.write_policy(original)


@pytest.fixture
def original_policy() -> str:
    return harness.POLICY_FILE.read_text(encoding="utf-8")


@pytest.fixture
def set_models():
    """set_models(fn) calls fn(doc) on a copy of the catalogue and writes it; restored afterwards."""
    yield from stack_config.config_setter(stack_config.MODELS_FILE)


@pytest.fixture
def set_teams():
    yield from stack_config.config_setter(stack_config.TEAMS_FILE)


@pytest.fixture(scope="module")
def admin(stack):
    """An admin API client for the test stack's admin panel."""
    admin_client.wait_ui()
    return admin_client.Admin()
