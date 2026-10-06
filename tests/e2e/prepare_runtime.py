"""Prepare tests/e2e/runtime/ before the test stack starts. Run by `make test-up`.

The gateway container runs as root, so any file it creates in a mounted folder is owned by root
on the host and the tests could not rewrite it. Both runtime files are therefore created here,
by the host user, before the container starts.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNTIME = REPO / "tests" / "e2e" / "runtime"
FIXTURES = REPO / "tests" / "fixtures" / "config"
TEST_PORTS = tuple(
    int(os.environ.get(name, default))
    for name, default in (
        ("CTRL_AI_GATEWAY_PORT", 4000),
        ("CTRL_AI_STUB_ANTHROPIC_PORT", 9001),
        ("CTRL_AI_STUB_JEV_PORT", 9002),
        ("CTRL_AI_UI_PORT", 4100),
    )
)


def ports_in_use(ports: tuple[int, ...]) -> list[int]:
    """Ports on 127.0.0.1 that already accept connections."""
    busy = []
    for port in ports:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                busy.append(port)
    return busy


def main() -> int:
    busy = ports_in_use(TEST_PORTS)
    if busy:
        print(
            f"Port(s) {', '.join(map(str, busy))} already in use. The test stack needs "
            f"{', '.join(map(str, TEST_PORTS))}. Stop the normal gateway (`make down`) or a previous test stack "
            "(`make test-down`) first.",
            file=sys.stderr,
        )
        return 1

    RUNTIME.mkdir(parents=True, exist_ok=True)
    # runtime state (gateway keys, break-glass overrides, config history), created by the
    # host user before the containers start.
    state = RUNTIME / "state"
    (state / "history").mkdir(parents=True, exist_ok=True)
    for name, empty in (("keys.json", {"keys": []}), ("break_glass.json", {"overrides": []})):
        with open(state / name, "w", encoding="utf-8") as handle:
            json.dump(empty, handle)
    (RUNTIME / "admin.jsonl").open("w", encoding="utf-8").close()
    # Copies of the frozen test configuration; tests may rewrite them.
    for name in ("models.yaml", "teams.yaml", "signatures.yaml", "mcp.yaml"):
        shutil.copyfile(FIXTURES / name, RUNTIME / name)
    # The gateway service also mounts ./logs. If it is missing, Docker creates it as root and a
    # later `make up` cannot create logs/audit.jsonl in it.
    (REPO / "logs").mkdir(exist_ok=True)
    shutil.copyfile(FIXTURES / "policy.yaml", RUNTIME / "policy.yaml")

    audit = RUNTIME / "audit.jsonl"
    try:
        # Opening with "w" both creates and empties it, without replacing the inode.
        audit.open("w", encoding="utf-8").close()
    except PermissionError:
        print(
            f"{audit} is not writable by this user; it was probably created by the container "
            "(root). Remove it with sudo and run again.",
            file=sys.stderr,
        )
        return 1
    print(f"runtime ready: configuration from {FIXTURES.relative_to(REPO)}; audit log emptied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
