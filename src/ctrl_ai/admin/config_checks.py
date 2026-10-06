"""The checks a configuration file must pass before the admin panel saves it.

The JSON Schema first; on a schema-valid document, the checks a schema cannot express, across
files: profiles that teams use, models that teams and budgets name, rule ids that break-glass
must never relax, duplicate ids. Pure: the store passes in the documents it read.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import jsonschema

from ctrl_ai.admin import regex_guard
from ctrl_ai.detect import packs

BUILTIN_PROFILES = ("observe", "balanced", "strict")
# Rule ids per built-in pack, for the policy page and the never_relax check.
PACK_RULES = {pack_id: list(packs.rule_ids(pack_id)) for pack_id in packs.PACK_IDS}
PACK_LABELS = {pack.id: pack.label for pack in packs.PACKS.values()}
CONTROL_NAMES = {"semantic", "budget", "loops", "model-banned", "masking", "normalisation"}


@dataclass
class Error:
    path: str
    message: str

    def to_dict(self) -> dict:
        return {"path": self.path, "message": self.message}


def schema_errors(schema: dict, doc: dict) -> list[Error]:
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


def policy_errors(doc: dict, teams: dict, signatures: dict) -> list[Error]:
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


def models_errors(doc: dict, teams: dict) -> list[Error]:
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


def teams_errors(doc: dict, models: dict, policy: dict) -> list[Error]:
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


def mcp_errors(doc: dict) -> list[Error]:
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


def cross_file_errors(name: str, doc: dict, other: Callable[[str], dict]) -> list[Error]:
    """The checks across files for a schema-valid document; ``other`` gives the other documents
    (``teams``, ``models``, ``policy``, ``signatures``)."""
    if name == "policy":
        return policy_errors(doc, other("teams"), other("signatures"))
    if name == "models":
        return models_errors(doc, other("teams"))
    if name == "teams":
        return teams_errors(doc, other("models"), other("policy"))
    if name == "mcp":
        return mcp_errors(doc)
    return []


# ---------------------------------------------------------------- key order for rendering


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
