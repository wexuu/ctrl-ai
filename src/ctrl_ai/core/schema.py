"""Validate configuration documents against the JSON Schemas in ``config/schema/``.

The schemas are the contract with the admin panel. The directory is the repository's
``config/schema`` unless the process's settings name another one (``CTRL_AI_SCHEMA_DIR``):
the gateway runtime and the admin app call ``use_schema_dir`` once when they start.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any

import jsonschema


class SchemaError(ValueError):
    """A document does not match its schema."""


DEFAULT_SCHEMA_DIR = Path(__file__).resolve().parents[3] / "config" / "schema"


class _SchemaDirectory:
    """Where the schemas are; set once at start-up by the process that owns the settings."""

    path: Path = DEFAULT_SCHEMA_DIR


def use_schema_dir(directory: str | Path | None) -> None:
    """Validate against the schemas in ``directory`` from now on (the default when empty)."""
    _SchemaDirectory.path = Path(directory) if directory else DEFAULT_SCHEMA_DIR


def schema_dir() -> Path:
    return _SchemaDirectory.path


@functools.lru_cache(maxsize=16)
def _validator(name: str, directory: str) -> Any:
    path = Path(directory) / f"{name}.schema.json"
    if not path.is_file():
        return None
    schema = json.loads(path.read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def jsonable(doc: Any) -> Any:
    """YAML dates become strings, as the schemas expect."""
    return json.loads(json.dumps(doc, default=str))


def validate(doc: Any, name: str) -> None:
    """Raise SchemaError with a short reason when ``doc`` does not match ``<name>.schema.json``.

    A missing schema file skips validation; our own parsers still check what they need.
    """
    validator = _validator(name, str(schema_dir()))
    if validator is None:
        return
    errors = sorted(validator.iter_errors(jsonable(doc)), key=lambda e: list(e.path))
    if errors:
        err = errors[0]
        where = "/".join(str(p) for p in err.path) or "(top level)"
        raise SchemaError(f"{where}: {err.message[:200]}")
