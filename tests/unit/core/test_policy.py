from __future__ import annotations

import os
from pathlib import Path

import pytest

from ctrl_ai.core.policy import DEFAULT_POLICY, PolicyError, PolicyStore, parse_policy

FIXTURE_POLICY = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "config" / "policy.yaml"

VALID = """\
mode: enforce
scan: last_user_message
rules:
  - id: test-marker
    type: contains
    value: "CTRL-AI-BLOCK-TEST"
  - id: aws-access-key
    type: regex
    value: "AKIA[0-9A-Z]{16}"
jev:
  enabled: false
"""


def write(path, text: str, mtime_ns: int | None = None) -> None:
    path.write_text(text, encoding="utf-8")
    if mtime_ns is not None:
        os.utime(path, ns=(mtime_ns, mtime_ns))


def test_valid_load(tmp_path):
    path = tmp_path / "policy.yaml"
    write(path, VALID)
    store = PolicyStore(str(path))
    policy = store.current()
    assert policy.mode == "enforce"
    assert [(r.id, r.type, r.value) for r in policy.rules] == [
        ("test-marker", "contains", "CTRL-AI-BLOCK-TEST"),
        ("aws-access-key", "regex", "AKIA[0-9A-Z]{16}"),
    ]
    assert policy.rules[0].pattern is None
    assert policy.rules[1].pattern is not None
    assert policy.jev_enabled is False
    assert len(policy.version) == 8 and int(policy.version, 16) >= 0
    assert store.last_error is None


def test_minimal_file_defaults(tmp_path):
    path = tmp_path / "policy.yaml"
    write(path, "mode: monitor\n")
    policy = PolicyStore(str(path)).current()
    assert (policy.mode, policy.rules, policy.jev_enabled) == ("monitor", (), True)


def test_fixture_policy_file():
    policy = parse_policy(FIXTURE_POLICY.read_bytes())
    assert policy.mode == "enforce"
    assert [r.id for r in policy.rules] == ["test-marker", "aws-access-key", "private-key"]
    assert policy.jev_enabled is True


def test_reload_after_change_and_version_changes(tmp_path):
    path = tmp_path / "policy.yaml"
    write(path, VALID)
    store = PolicyStore(str(path))
    first = store.current()
    # Same size, so only the mtime shows the change. Coarse filesystem timestamps (ext4) can give
    # two quick writes the same mtime, so move it forward explicitly.
    write(
        path,
        VALID.replace("mode: enforce", "mode: monitor"),
        mtime_ns=os.stat(path).st_mtime_ns + 1_000_000_000,
    )
    second = store.current()
    assert second.mode == "monitor"
    assert second.version != first.version


def test_reload_when_only_the_size_changes(tmp_path):
    path = tmp_path / "policy.yaml"
    write(path, "mode: enforce\n", mtime_ns=1_000_000_000)
    store = PolicyStore(str(path))
    assert store.current().mode == "enforce"
    write(path, "mode: monitor\nrules: []\n", mtime_ns=1_000_000_000)
    assert store.current().mode == "monitor"


def test_unchanged_file_is_not_read_again(tmp_path, monkeypatch):
    path = tmp_path / "policy.yaml"
    write(path, VALID)
    store = PolicyStore(str(path))
    first = store.current()

    def fail(*args, **kwargs):
        raise AssertionError("the policy file was re-read")

    monkeypatch.setattr("builtins.open", fail)
    assert store.current() is first


def test_invalid_file_keeps_last_good_policy(tmp_path):
    path = tmp_path / "policy.yaml"
    write(path, VALID)
    store = PolicyStore(str(path))
    good = store.current()
    write(path, "mode: sometimes\n")
    assert store.current() is good
    assert "mode" in store.last_error
    write(path, VALID.replace("enabled: false", "enabled: true"))
    assert store.current().jev_enabled is True
    assert store.last_error is None


def test_bad_file_is_not_retried_on_every_request(tmp_path, monkeypatch):
    path = tmp_path / "policy.yaml"
    write(path, "mode: [broken\n")
    store = PolicyStore(str(path))
    assert store.current() is DEFAULT_POLICY
    error = store.last_error
    assert error

    def fail(*args, **kwargs):
        raise AssertionError("the bad policy file was re-read")

    monkeypatch.setattr("builtins.open", fail)
    assert store.current() is DEFAULT_POLICY
    assert store.last_error == error


def test_missing_file_gives_the_default(tmp_path):
    store = PolicyStore(str(tmp_path / "absent.yaml"))
    policy = store.current()
    assert (policy.mode, policy.rules, policy.jev_enabled, policy.version) == ("monitor", (), True, "default")
    assert store.last_error


def test_file_that_disappears_keeps_last_good_policy(tmp_path):
    path = tmp_path / "policy.yaml"
    write(path, VALID)
    store = PolicyStore(str(path))
    good = store.current()
    path.rename(tmp_path / "moved.yaml")
    assert store.current() is good
    assert store.last_error


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("- just\n- a list\n", "mapping"),
        ("rules: []\n", "mode"),
        ("mode: enforce\nscan: everything\n", "scan"),
        ("mode: enforce\nrules: {}\n", "rules must be a list"),
        (
            "mode: enforce\nrules:\n  - id: a\n    type: contains\n    value: x\n"
            "  - id: a\n    type: contains\n    value: y\n",
            "duplicate",
        ),
        ("mode: enforce\nrules:\n  - id: ''\n    type: contains\n    value: x\n", "non-empty id"),
        ("mode: enforce\nrules:\n  - type: contains\n    value: x\n", "non-empty id"),
        ("mode: enforce\nrules:\n  - id: a\n    type: glob\n    value: x\n", "type"),
        ("mode: enforce\nrules:\n  - id: a\n    type: contains\n    value: ''\n", "value"),
        ("mode: enforce\nrules:\n  - id: a\n    type: regex\n    value: '(unclosed'\n", "regex"),
        ("mode: enforce\njev:\n  enabled: maybe\n", "jev.enabled"),
        ("mode: enforce\njev: off\n", "jev.enabled"),
    ],
)
def test_invalid_files_are_rejected(text, fragment):
    with pytest.raises(PolicyError, match=fragment):
        parse_policy(text.encode())
