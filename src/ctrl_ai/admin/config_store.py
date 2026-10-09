"""Read, validate, save, version and roll back the configuration files the admin panel manages.

Pure Python (PyYAML and jsonschema only), unit-testable on the host. Every save is validated
against the JSON Schema contract in config/schema/ plus the checks a schema cannot express
(``config_checks.py``),
refused on a version conflict, copied to the history folder, written atomically and recorded
in the admin audit log. The gateway re-reads the files on its own (live reload).
"""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import yaml

from ctrl_ai.admin import admin_audit
from ctrl_ai.admin.config_checks import Error, cross_file_errors, ordered, schema_errors
from ctrl_ai.admin.settings import AdminSettings
from ctrl_ai.core.schema import jsonable

REPO = Path(__file__).resolve().parents[3]
# Managed file -> (the AdminSettings field with its path, its schema).
FILES = {
    "policy": ("policy_file", "policy.schema.json"),
    "models": ("models_file", "models.schema.json"),
    "teams": ("teams_file", "teams.schema.json"),
    "mcp": ("mcp_file", "mcp.schema.json"),
}
HEADERS = {
    "policy": """\
# ctrl-ai policy. Schema: config/schema/policy.schema.json.
#
# The gateway re-reads this file whenever it changes: save it and the next
# request uses it, no restart. If the file is invalid it is ignored and the
# last valid version stays active. Saved from the admin panel (Policy page),
# which validates it first and keeps every previous version in state/history/.
#
# mode      enforce: a request that matches a blocking rule is refused (HTTP 400).
#           monitor: nothing is refused; the audit log records would_block: true.
# profiles  per-team behaviour (observe, balanced, strict or custom): mode,
#           what a high semantic score does, what happens when Jev is down.
# rule_packs  built-in detectors: pii (e-mail, phone, cards, IBAN), pl (PESEL,
#           NIP, NRB account), secrets (keys and tokens), signatures (known
#           exploit feed); rule ids in src/ctrl_ai/detect/packs.py.
# rules     custom rules, tried top to bottom; an entry with a pack rule's id
#           overrides that pack rule (action, enabled).
#             id     a unique name; it appears in the refusal and the audit log
#             type   contains (exact text) or regex (Python regular expression)
#             value  what to look for
# jev       the semantic check: thresholds for review and block.
# judge     the second model (gpt-oss-safeguard-20b): confirms Jev's rejections, decides alone when
#           Jev is down or off; block_message is the refusal the agent sees ({score} {category}
#           {reason} {model}); shadow re-checks a share of what Jev accepted (misses, drift).
""",
    "models": """\
# ctrl-ai model catalogue: which models may be used, by whom, for which data, at what price.
# Schema: config/schema/models.schema.json. Edited from the admin panel (Models page) or by
# hand; the gateway picks changes up without a restart.
""",
    "teams": """\
# Departments and teams of the organisation. Schema: config/schema/teams.schema.json.
# Gateway keys are issued per team from the admin panel and stored as hashes in state/keys.json.
# Edited from the admin panel (Teams page); the gateway picks changes up without a restart.
""",
    "mcp": """\
# Approved MCP tool servers. Schema: config/schema/mcp.schema.json.
# Tool descriptions are pinned by hash (description_sha256); a changed description suspends the
# tool until it is reviewed and re-pinned in the admin panel (Tools page).
""",
}


class StoreError(Exception):
    """A refused operation, with the HTTP status the API should answer."""

    def __init__(
        self, status: int, message: str, errors: list | None = None, current_version: str | None = None
    ):
        super().__init__(message)
        self.status = status
        self.message = message
        self.errors = errors or []
        self.current_version = current_version

    def to_dict(self) -> dict:
        out = {"error": self.message, "errors": self.errors}
        if self.current_version:
            out["current_version"] = self.current_version
        return out


# ---------------------------------------------------------------- paths and reading


def path_of(settings: AdminSettings, name: str) -> Path:
    if name not in FILES:
        raise StoreError(404, f"unknown config file {name!r}")
    return Path(getattr(settings, FILES[name][0]))


def schema_dir(settings: AdminSettings) -> Path:
    configured = Path(settings.schema_dir)
    return configured if configured.is_dir() else REPO / "config" / "schema"


def load_schema(settings: AdminSettings, file_name: str) -> dict:
    return json.loads((schema_dir(settings) / file_name).read_text(encoding="utf-8"))


def history_dir(settings: AdminSettings) -> Path:
    return Path(settings.history_dir)


def version_of(raw: bytes) -> str:
    """First 8 hex characters of the SHA-256 of the bytes."""
    return hashlib.sha256(raw).hexdigest()[:8]


def read(settings: AdminSettings, name: str) -> tuple[dict, str, str]:
    """(doc, text, version) of a managed file. A missing file is an empty document."""
    path = path_of(settings, name)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        empty = {
            "mcp": {"servers": []},
            "teams": {"departments": [], "teams": []},
            "models": {"models": []},
            "policy": {"mode": "enforce"},
        }[name]
        return empty, "", version_of(b"")
    text = raw.decode("utf-8", "replace")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        doc = None
    return (jsonable(doc) if isinstance(doc, dict) else {}), text, version_of(raw)


def read_doc(settings: AdminSettings, name: str) -> dict:
    return read(settings, name)[0]


# ---------------------------------------------------------------- validation


def signatures_doc(settings: AdminSettings) -> dict:
    path = Path(settings.signatures_file)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return jsonable(doc) if isinstance(doc, dict) else {}


def validate(settings: AdminSettings, name: str, doc, *, others: dict | None = None) -> list[Error]:
    """Schema errors first; the cross-file checks only run on a schema-valid document.

    `others` can supply the other documents (name -> doc) instead of reading them from disk.
    """
    others = others or {}
    if not isinstance(doc, dict):
        return [Error("(root)", "the document must be a mapping")]
    doc = jsonable(doc)
    errors = schema_errors(load_schema(settings, FILES[name][1]), doc)
    if errors:
        return errors

    def other(n: str) -> dict:
        if n == "signatures":
            return others.get("signatures") or signatures_doc(settings)
        return others[n] if n in others else read_doc(settings, n)

    return cross_file_errors(name, doc, other)


# ---------------------------------------------------------------- rendering


class _Dumper(yaml.SafeDumper):
    """Block style, but short lists of scalars inline (as in the hand-written files)."""


def _repr_list(dumper, data):
    flow = len(data) <= 8 and all(isinstance(x, (str, int, float, bool)) and len(str(x)) < 40 for x in data)
    return dumper.represent_sequence("tag:yaml.org,2002:seq", data, flow_style=flow)


_Dumper.add_representer(list, _repr_list)


def render(settings: AdminSettings, name: str, doc: dict) -> str:
    """YAML text: the fixed header comment, keys in schema order."""
    schema = load_schema(settings, FILES[name][1])
    body = yaml.dump(
        ordered(jsonable(doc), schema, schema),
        Dumper=_Dumper,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=110,
    )
    return HEADERS[name] + "\n" + body


# ---------------------------------------------------------------- writing


def atomic_write(path: Path, data: bytes) -> None:
    """Temp file in the same directory, fsync, os.replace: readers see the old or the new file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def _check_reason(reason: str | None) -> str:
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise StoreError(
            422,
            "A reason of at least 3 characters is required",
            [Error("reason", "at least 3 characters").to_dict()],
        )
    return reason[:300]


def save(
    settings: AdminSettings,
    name: str,
    doc: dict,
    *,
    expected_version: str | None,
    actor: str,
    reason: str,
    action: str | None = None,
) -> str:
    """Validate and write a managed file; returns the new version. Raises StoreError (409/422)."""
    reason = _check_reason(reason)
    path = path_of(settings, name)
    _, _old_text, current = read(settings, name)
    if expected_version != current:
        raise StoreError(
            409, "The file was changed by someone else; reload and try again.", current_version=current
        )
    errors = validate(settings, name, doc)
    if errors:
        raise StoreError(422, "Validation failed", [e.to_dict() for e in errors])
    new_bytes = render(settings, name, doc).encode("utf-8")
    if path.exists():
        hist = history_dir(settings) / name
        hist.mkdir(parents=True, exist_ok=True)
        atomic_write(hist / f"{_stamp()}-{current}.yaml", path.read_bytes())
    atomic_write(path, new_bytes)
    new_version = version_of(new_bytes)
    admin_audit.write(
        settings.admin_audit_log,
        action or f"{name}.save",
        actor=actor,
        target=path.name,
        version_before=current,
        version_after=new_version,
        reason=reason,
    )
    return new_version


def history(settings: AdminSettings, name: str) -> list[dict]:
    """Saved previous versions, newest first: timestamp, version, size, file."""
    folder = history_dir(settings) / name
    out = []
    if folder.is_dir():
        for f in sorted(folder.glob("*.yaml"), reverse=True):
            m = re.match(r"^(\d{8}T\d{6})(\d*)Z-([0-9a-f]{8})\.yaml$", f.name)
            if not m:
                continue
            stamp = datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=UTC)
            out.append(
                {
                    "ts": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "version": m.group(3),
                    "size": f.stat().st_size,
                    "file": f.name,
                }
            )
    return out


def _history_file(settings: AdminSettings, name: str, version: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{8}", version or ""):
        raise StoreError(404, "unknown version")
    for entry in history(settings, name):
        if entry["version"] == version:
            return history_dir(settings) / name / entry["file"]
    raise StoreError(404, f"version {version} is not in the history of {name}")


def diff(settings: AdminSettings, name: str, version: str) -> str:
    """Unified diff from a saved version to the current file."""
    old = _history_file(settings, name, version).read_text(encoding="utf-8", errors="replace")
    _, current_text, current = read(settings, name)
    lines = difflib.unified_diff(
        old.splitlines(keepends=True),
        current_text.splitlines(keepends=True),
        fromfile=f"{name} {version}",
        tofile=f"{name} {current} (current)",
    )
    return "".join(lines)


def rollback(settings: AdminSettings, name: str, version: str, *, actor: str, reason: str) -> str:
    """Re-validate a saved version against today's schema and save it as a new version."""
    reason = _check_reason(reason)
    text = _history_file(settings, name, version).read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise StoreError(422, f"saved version is not valid YAML ({type(exc).__name__})") from exc
    _, _, current = read(settings, name)
    return save(
        settings,
        name,
        doc if isinstance(doc, dict) else {},
        expected_version=current,
        actor=actor,
        reason=f"rollback to {version}: {reason}",
        action=f"{name}.rollback",
    )


# ---------------------------------------------------------------- JSON state files (keys, break-glass)


def state_path(settings: AdminSettings, kind: str) -> Path:
    if kind == "keys":
        return Path(settings.keys_file)
    if kind == "break_glass":
        return Path(settings.break_glass_file)
    raise StoreError(404, f"unknown state file {kind!r}")


def read_state(settings: AdminSettings, kind: str) -> dict:
    root = "keys" if kind == "keys" else "overrides"
    try:
        doc = json.loads(state_path(settings, kind).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {root: []}
    if not isinstance(doc, dict) or not isinstance(doc.get(root), list):
        return {root: []}
    return doc


def write_state(settings: AdminSettings, kind: str, doc: dict) -> None:
    """Validate against the schema, then write atomically."""
    schema = load_schema(settings, "keys.schema.json" if kind == "keys" else "break_glass.schema.json")
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = [e.message for e in validator.iter_errors(doc)]
    if errors:
        raise StoreError(
            422, "state file would be invalid", [{"path": "(root)", "message": m} for m in errors[:5]]
        )
    atomic_write(state_path(settings, kind), (json.dumps(doc, indent=2) + "\n").encode("utf-8"))
