"""Nothing secret or private reached the audit log. Named to sort last, after every other test."""

from __future__ import annotations

from tests.e2e import harness as h
from tests.e2e.constants import FAKE_OAUTH_TOKEN, TEST_JEV_KEY, TEST_PROVIDER_KEY


def test_no_secrets_or_prompts_in_audit_log():
    """The audit file holds no key, token or prompt text used in the suite."""
    text = h.AUDIT_FILE.read_text(encoding="utf-8", errors="replace")
    secrets = {
        "gateway test key": h.TEST_KEY,
        "dummy provider key": TEST_PROVIDER_KEY,
        "fake OAuth token": FAKE_OAUTH_TOKEN,
        "Jev test key": TEST_JEV_KEY,
    }
    found = [name for name, value in secrets.items() if value in text]
    assert not found, f"secrets found in the audit log: {found}"
    # Every prompt carries a unique "e2e-prompt-" tag, so this catches prompts from any test, even a
    # partial copy. ("e2e-" alone is not enough: it occurs in random UUIDs such as request ids.)
    assert "e2e-prompt-" not in text, "prompt text found in the audit log"
    leaked = sum(1 for p in h.PROMPTS_SENT if p in text)
    assert leaked == 0, f"{leaked} prompt(s) found in the audit log"
