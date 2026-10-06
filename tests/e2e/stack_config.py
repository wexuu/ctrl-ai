"""Test helper: rewrite the test stack's catalogue and teams, restore afterwards."""

from __future__ import annotations

import os
import time

import yaml

from tests.e2e import harness as h

MODELS_FILE = h.RUNTIME / "models.yaml"
TEAMS_FILE = h.RUNTIME / "teams.yaml"


def write_in_place(path, text: str) -> None:
    before = path.stat().st_mtime if path.exists() else 0.0
    with path.open("w", encoding="utf-8") as f:
        f.write(text)
    mtime = max(time.time(), before + 2.0)
    os.utime(path, (mtime, mtime))


def _fixture(path):
    original = path.read_text(encoding="utf-8")
    changed = False

    def _set(doc_or_fn) -> None:
        nonlocal changed
        changed = True
        doc = yaml.safe_load(original)
        if callable(doc_or_fn):
            doc_or_fn(doc)
        else:
            doc = doc_or_fn
        write_in_place(path, yaml.safe_dump(doc, sort_keys=False))

    return original, _set, lambda: changed


def config_setter(path):
    """Yield a setter for one config file of the test stack; the original is restored afterwards.

    The setter takes a document, or a function that edits a copy of the current document.
    """
    original, setter, changed = _fixture(path)
    yield setter
    if changed():
        write_in_place(path, original)


def model(doc: dict, model_id: str) -> dict:
    return next(m for m in doc["models"] if m["id"] == model_id)
