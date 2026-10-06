"""Read, validate, save, version and roll back the configuration files the admin panel manages.

Pure Python (PyYAML and jsonschema only), unit-testable on the host. Every save is validated
against the JSON Schema contract in config/schema/ plus the checks a schema cannot express,
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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import yaml

from ctrl_ai.admin import admin_audit, regex_guard
from ctrl_ai.admin.settings import AdminSettings
from ctrl_ai.detect import packs

REPO = Path(__file__).resolve().parents[3]
# Managed file -> (the AdminSettings field with its path, its schema).
FILES = {
    "policy": ("policy_file", "policy.schema.json"),
    "models": ("models_file", "models.schema.json"),
    "teams": ("teams_file", "teams.schema.json"),
    "mcp": ("mcp_file", "mcp.schema.json"),
}
BUILTIN_PROFILES = ("observe", "balanced", "strict")
# Rule ids per built-in pack, for the policy page and the never_relax check.
PACK_RULES = {pack_id: list(packs.rule_ids(pack_id)) for pack_id in packs.PACK_IDS}
PACK_LABELS = {pack.id: pack.label for pack in packs.PACKS.values()}
CONTROL_NAMES = {"semantic", "budget", "loops", "model-banned", "masking", "normalisation"}

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
#           exploit feed). docs/CONFIGURATION.md lists their rule ids.
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


@dataclass
class Error:
    path: str
    message: str

    def to_dict(self) -> dict:
        return {"path": self.path, "message": self.message}


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


def jsonable(doc):
    """YAML dates become strings, so JSON Schema and JSON responses accept them."""
    return json.loads(json.dumps(doc, default=str))


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


def _schema_errors(settings: AdminSettings, name: str, doc: dict) -> list[Error]:
    schema = load_schema(settings, FILES[name][1])
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        path = "/".join(str(p) for p in err.absolute_path)
        errors.append(Error(path or "(root)", err.message))
    return errors


def profiles_of(policy: dict) -> list[str]:
    """Profile names the policy defines; the three built-ins when it defines none (v1 file)."""
    profiles = policy.get("profiles")
    if isinstance(profiles, dict) and profiles:
        return list(profiles)
    return list(BUILTIN_PROFILES)


def model_matches(model_id: str, name: str) -> bool:
    """A catalogue id matches a model name exactly, or as a prefix when it ends with *."""
    if model_id.endswith("*"):
        return name.startswith(model_id[:-1])
    return model_id == name


def find_model(models: dict, name: str) -> dict | None:
    entries = [m for m in models.get("models", []) if isinstance(m, dict)]
    for m in entries:
        if m.get("id") == name:
            return m
    for m in entries:
        if isinstance(m.get("id"), str) and model_matches(m["id"], name):
            return m
    return None


def allowed_for_team(model: dict | None, team: str) -> bool:
    if not model or model.get("status") == "banned":
        return False
    teams = model.get("teams") or []
    return "*" in teams or team in teams


def _policy_checks(doc: dict, teams: dict, signatures: dict) -> list[Error]:
    errs: list[Error] = []
    profiles = profiles_of(doc)
    default = doc.get("default_profile")
    if default is not None and default not in profiles:
        errs.append(Error("default_profile", f"profile {default!r} is not defined in profiles"))
    for team in teams.get("teams", []) or []:
        prof = team.get("profile") if isinstance(team, dict) else None
        if prof and prof not in profiles:
            errs.append(
                Error(
                    "profiles", f"team {team.get('id')!r} uses profile {prof!r}, which would no longer exist"
                )
            )
    seen = set()
    for i, rule in enumerate(doc.get("rules", []) or []):
        if not isinstance(rule, dict):
            continue
        rid = rule.get("id")
        if rid in seen:
            errs.append(Error(f"rules/{i}/id", f"duplicate rule id {rid!r}"))
        seen.add(rid)
        if rule.get("type") == "regex" and isinstance(rule.get("value"), str):
            problem = regex_guard.check(rule["value"])
            if problem:
                errs.append(Error(f"rules/{i}/value", f"regex {problem}"))
    jev = doc.get("jev") or {}
    review, block = jev.get("review_threshold"), jev.get("block_threshold")
    if isinstance(review, (int, float)) and isinstance(block, (int, float)) and not review < block:
        errs.append(Error("jev/review_threshold", "review_threshold must be lower than block_threshold"))
    never = ((doc.get("break_glass") or {}).get("never_relax")) or []
    known = set(seen) | CONTROL_NAMES | set(PACK_RULES)
    for ids in PACK_RULES.values():
        known |= set(ids)
    known |= {s.get("id") for s in signatures.get("signatures", []) or [] if isinstance(s, dict)}
    for i, name in enumerate(never):
        if name not in known:
            errs.append(
                Error(f"break_glass/never_relax/{i}", f"{name!r} is not a known rule, pack or control")
            )
    return errs


def _models_checks(doc: dict, teams: dict) -> list[Error]:
    errs: list[Error] = []
    entries = [m for m in doc.get("models", []) or [] if isinstance(m, dict)]
    by_id = {}
    for i, m in enumerate(entries):
        if m.get("id") in by_id:
            errs.append(Error(f"models/{i}/id", f"duplicate model id {m.get('id')!r}"))
        by_id[m.get("id")] = m
    team_ids = {t.get("id") for t in teams.get("teams", []) or [] if isinstance(t, dict)}
    for i, m in enumerate(entries):
        mid = str(m.get("id", ""))
        for field in ("equivalent",):
            target = m.get(field)
            if target is not None:
                if target not in by_id:
                    errs.append(Error(f"models/{i}/{field}", f"{target!r} is not in the catalogue"))
                elif by_id[target].get("status") == "banned":
                    errs.append(Error(f"models/{i}/{field}", f"{target!r} is banned"))
        for j, target in enumerate(m.get("fallbacks") or []):
            if target not in by_id:
                errs.append(Error(f"models/{i}/fallbacks/{j}", f"{target!r} is not in the catalogue"))
            elif by_id[target].get("status") == "banned":
                errs.append(Error(f"models/{i}/fallbacks/{j}", f"{target!r} is banned"))
        if m.get("status") == "approved" and "price" not in m and not mid.endswith("*"):
            errs.append(Error(f"models/{i}/price", "an approved model needs a price"))
        if m.get("status") == "deprecated" and not m.get("sunset"):
            errs.append(Error(f"models/{i}/sunset", "a deprecated model needs a sunset date"))
        for j, team in enumerate(m.get("teams") or []):
            if team != "*" and team_ids and team not in team_ids:
                errs.append(Error(f"models/{i}/teams/{j}", f"team {team!r} does not exist in teams.yaml"))
    return errs


def _teams_checks(doc: dict, models: dict, policy: dict) -> list[Error]:
    errs: list[Error] = []
    deps = [d for d in doc.get("departments", []) or [] if isinstance(d, dict)]
    dep_ids = set()
    for i, d in enumerate(deps):
        if d.get("id") in dep_ids:
            errs.append(Error(f"departments/{i}/id", f"duplicate department id {d.get('id')!r}"))
        dep_ids.add(d.get("id"))
    profiles = profiles_of(policy)
    seen = set()
    for i, t in enumerate(doc.get("teams", []) or []):
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if tid in seen:
            errs.append(Error(f"teams/{i}/id", f"duplicate team id {tid!r}"))
        seen.add(tid)
        if t.get("department") not in dep_ids:
            errs.append(Error(f"teams/{i}/department", f"department {t.get('department')!r} does not exist"))
        if t.get("profile") and t["profile"] not in profiles:
            errs.append(Error(f"teams/{i}/profile", f"profile {t['profile']!r} is not defined in the policy"))
        checks = [("default_model", t.get("default_model"))]
        budget = t.get("budget") or {}
        checks.append(("budget/downgrade_to", budget.get("downgrade_to")))
        for field, name in checks:
            if not name:
                continue
            model = find_model(models, name)
            if model is None:
                errs.append(Error(f"teams/{i}/{field}", f"model {name!r} is not in the catalogue"))
            elif not allowed_for_team(model, str(tid)):
                errs.append(Error(f"teams/{i}/{field}", f"model {name!r} is not allowed for team {tid!r}"))
        if budget.get("on_exceeded") == "downgrade" and not budget.get("downgrade_to"):
            errs.append(Error(f"teams/{i}/budget/downgrade_to", "on_exceeded: downgrade needs downgrade_to"))
    return errs


def _mcp_checks(doc: dict) -> list[Error]:
    errs: list[Error] = []
    seen = set()
    for i, s in enumerate(doc.get("servers", []) or []):
        if not isinstance(s, dict):
            continue
        if s.get("name") in seen:
            errs.append(Error(f"servers/{i}/name", f"duplicate server name {s.get('name')!r}"))
        seen.add(s.get("name"))
        tools = set()
        for j, tool in enumerate(s.get("tools") or []):
            if isinstance(tool, dict) and tool.get("name") in tools:
                errs.append(Error(f"servers/{i}/tools/{j}/name", f"duplicate tool {tool.get('name')!r}"))
            if isinstance(tool, dict):
                tools.add(tool.get("name"))
    return errs


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
    errors = _schema_errors(settings, name, doc)
    if errors:
        return errors

    def other(n: str) -> dict:
        return others[n] if n in others else read_doc(settings, n)

    if name == "policy":
        return _policy_checks(doc, other("teams"), others.get("signatures") or signatures_doc(settings))
    if name == "models":
        return _models_checks(doc, other("teams"))
    if name == "teams":
        return _teams_checks(doc, other("models"), other("policy"))
    if name == "mcp":
        return _mcp_checks(doc)
    return []


# ---------------------------------------------------------------- rendering


def _resolve(schema: dict, root: dict) -> dict:
    ref = schema.get("$ref") if isinstance(schema, dict) else None
    if ref and ref.startswith("#/$defs/"):
        return root.get("$defs", {}).get(ref.split("/")[-1], {})
    return schema if isinstance(schema, dict) else {}


def ordered(doc, schema: dict, root: dict):
    """The document with mapping keys in schema order (unknown keys last), recursively."""
    schema = _resolve(schema, root)
    if isinstance(doc, dict):
        props = schema.get("properties") or {}
        extra = (
            schema.get("additionalProperties")
            if isinstance(schema.get("additionalProperties"), dict)
            else None
        )
        keys = [k for k in props if k in doc] + [k for k in doc if k not in props]
        out = {}
        for k in keys:
            sub = (props.get(k) if k in props else extra) or {}
            out[k] = ordered(doc[k], sub, root)
        return out
    if isinstance(doc, list):
        return [ordered(item, schema.get("items") or {}, root) for item in doc]
    return doc


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
