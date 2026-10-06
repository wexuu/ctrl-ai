"""Load, validate and hot-reload the policy file (``config/policy.yaml``).

Version 1 files (no ``version: 2``) have no rule packs, one implicit profile from
``mode`` and no judge. Version 2 adds profiles, rule packs, Jev
thresholds, the judge, normalisation, loop caps, masking and break-glass settings.
Every file is validated against ``config/schema/policy.schema.json`` (the contract
with the admin panel) after our own checks, which give the clearer messages.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from ctrl_ai.core.context import Profile
from ctrl_ai.core.schema import SchemaError, validate

MODES = ("enforce", "monitor")
RULE_TYPES = ("contains", "regex")
SCAN_MODES = ("last_user_message",)
DEFAULT_RULE_SOURCES = ("prompt", "tool_result")

DEFAULT_LOOPS = {
    "enabled": True,
    "max_requests_per_10_min": 300,
    "max_tokens_per_session": 2_000_000,
    "max_calls_per_user_turn": 80,
    "max_identical_tool_calls": 5,
}
DEFAULT_MASKING = {
    "enabled": True,
    "entities": ["iban", "pesel", "nip", "card", "email", "phone"],
    "routes": {"external": "mask", "claude_subscription": "semantic_copy_only"},
    "on_error": "fail_closed",
}
DEFAULT_NEVER_RELAX = ["secret-aws-key", "secret-private-key", "secret-github-token", "model-banned"]
DEFAULT_SHADOW = {"rate": 0.0, "samples": 5, "alert_below": 0.9, "min_checks": 10}
DEFAULT_SEMANTIC_OUTAGE = {
    "mode": "degrade",
    "strict_profiles_fail_closed": True,
    "circuit": {"failures_to_open": 5, "window_s": 60, "cooldown_s": 30},
    "max_manual_minutes": 120,
}
DEFAULT_BREAK_GLASS = {
    "enabled": True,
    "max_minutes": 240,
    "require_ticket": True,
    "never_relax": DEFAULT_NEVER_RELAX,
}


@dataclass(frozen=True)
class Rule:
    id: str
    type: str
    value: str
    pattern: re.Pattern[str] | None = field(default=None, compare=False, repr=False)
    action: str = "block"
    sources: tuple[str, ...] = DEFAULT_RULE_SOURCES
    severity: str = "high"
    enabled: bool = True


@dataclass(frozen=True)
class Policy:
    mode: str
    rules: tuple[Rule, ...]
    jev_enabled: bool
    version: str
    schema_version: int = 1
    profiles: dict[str, Profile] = field(default_factory=dict, compare=False)
    default_profile: str = "default"
    rule_packs: tuple[str, ...] = ()
    review_threshold: float = 0.35
    block_threshold: float = 0.70
    # Single-threshold flow: Jev accepts below accept_below, the judge decides the rest.
    accept_below: float | None = None
    judge_reject_from: float = 0.5
    jev_sources: tuple[str, ...] = ("prompt", "tool_result")
    judge_enabled: bool = False
    judge_when: tuple[str, ...] = ()
    # Refusal text when the judge blocks; placeholders {score} {category} {reason} {model}.
    judge_block_message: str | None = None
    shadow: dict = field(default_factory=lambda: dict(DEFAULT_SHADOW), compare=False)
    normalisation_enabled: bool = True
    hidden_char_threshold: int = 5
    loops: dict = field(default_factory=lambda: dict(DEFAULT_LOOPS), compare=False)
    masking: dict = field(default_factory=lambda: dict(DEFAULT_MASKING), compare=False)
    break_glass: dict = field(default_factory=lambda: dict(DEFAULT_BREAK_GLASS), compare=False)
    semantic_outage: dict = field(default_factory=lambda: dict(DEFAULT_SEMANTIC_OUTAGE), compare=False)

    def profile(self, name: str | None) -> Profile:
        """The named profile, else the default profile, else one built from ``mode``."""
        if name and name in self.profiles:
            return self.profiles[name]
        if self.default_profile in self.profiles:
            return self.profiles[self.default_profile]
        return Profile(name=self.default_profile, mode=self.mode)

    def effective_mode(self, profile: Profile, team_mode: str | None = None) -> str:
        """The mode a request runs in. A team's own ``mode`` (teams.yaml) decides when it is set.
        Otherwise a global ``mode: monitor`` is an organisation-wide switch to observe-only that wins over
        every profile, and under ``enforce`` the profile decides."""
        if team_mode in ("enforce", "monitor"):
            return team_mode
        if self.mode == "monitor" or self.schema_version != 2:
            return self.mode
        return profile.mode

    def rule_override(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None


# Used until a valid file has been loaded: observe everything, block nothing.
DEFAULT_POLICY = Policy(mode="monitor", rules=(), jev_enabled=True, version="default")


class PolicyError(ValueError):
    """The policy file does not match the schema."""


def parse_policy(raw: bytes) -> Policy:
    """Build a Policy from the bytes of a policy file, or raise PolicyError."""
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyError(f"not valid YAML ({type(exc).__name__})") from None
    if not isinstance(doc, dict):
        raise PolicyError("the file must be a mapping")

    mode = doc.get("mode")
    if mode not in MODES:
        raise PolicyError(f"mode must be one of {', '.join(MODES)}")
    if "scan" in doc and doc["scan"] not in SCAN_MODES:
        raise PolicyError(f"scan must be {SCAN_MODES[0]}")

    jev = doc.get("jev")
    if jev is None:
        jev = {}
    if not isinstance(jev, dict) or not isinstance(jev.get("enabled", True), bool):
        raise PolicyError("jev.enabled must be true or false")

    rules = _parse_rules(doc.get("rules"))
    _schema_check(doc)

    v2 = doc.get("version") == 2
    profiles = _parse_profiles(doc.get("profiles") or {})
    default_profile = doc.get("default_profile") or "default"
    if v2 and profiles and default_profile not in profiles:
        raise PolicyError(f"default_profile {default_profile!r} is not one of the profiles")
    judge = doc.get("judge") or {}
    normalisation = doc.get("normalisation") or {}
    review = float(jev.get("review_threshold", 0.35))
    block = float(jev.get("block_threshold", 0.70))
    if review > block:
        raise PolicyError("jev.review_threshold must not be above jev.block_threshold")
    masking = {**DEFAULT_MASKING, **(doc.get("masking") or {})}
    masking["routes"] = {**DEFAULT_MASKING["routes"], **((doc.get("masking") or {}).get("routes") or {})}
    return Policy(
        mode=mode,
        rules=rules,
        jev_enabled=jev.get("enabled", True),
        version=hashlib.sha256(raw).hexdigest()[:8],
        schema_version=2 if v2 else 1,
        profiles=profiles,
        default_profile=default_profile,
        rule_packs=tuple(doc.get("rule_packs") or ()) if v2 else (),
        review_threshold=review,
        block_threshold=block,
        accept_below=float(jev["accept_below"]) if jev.get("accept_below") is not None else None,
        judge_reject_from=float(judge.get("reject_from", 0.5)),
        jev_sources=tuple(jev.get("sources") or ("prompt", "tool_result")),
        judge_enabled=bool(judge.get("enabled", False)) if v2 else False,
        judge_when=tuple(judge.get("when") or ("jev_unavailable", "jev_uncertain")),
        judge_block_message=(judge.get("block_message") or "").strip() or None,
        shadow={**DEFAULT_SHADOW, **(judge.get("shadow") or {})},
        normalisation_enabled=bool(normalisation.get("enabled", True)),
        hidden_char_threshold=int(normalisation.get("hidden_char_threshold", 5)),
        loops={**DEFAULT_LOOPS, **(doc.get("loops") or {})} if v2 else {**DEFAULT_LOOPS, "enabled": False},
        masking=masking if v2 else {**masking, "enabled": False},
        break_glass={**DEFAULT_BREAK_GLASS, **(doc.get("break_glass") or {})},
        semantic_outage=_outage_settings(doc.get("semantic_outage") or {}),
    )


def _outage_settings(raw: dict) -> dict:
    out = {**DEFAULT_SEMANTIC_OUTAGE, **raw}
    out["circuit"] = {**DEFAULT_SEMANTIC_OUTAGE["circuit"], **(raw.get("circuit") or {})}
    return out


def _schema_check(doc: dict) -> None:
    try:
        validate(doc, "policy")
    except SchemaError as exc:
        raise PolicyError(f"schema: {exc}") from None


def _parse_profiles(raw: Any) -> dict[str, Profile]:
    if not isinstance(raw, dict):
        raise PolicyError("profiles must be a mapping")
    out = {}
    for name, spec in raw.items():
        if not isinstance(spec, dict) or spec.get("mode") not in MODES:
            raise PolicyError(f"profile {name}: mode must be one of {', '.join(MODES)}")
        out[str(name)] = Profile(
            name=str(name),
            mode=spec["mode"],
            semantic_action=spec.get("semantic_action", "observe"),
            on_semantic_unavailable=spec.get("on_semantic_unavailable", "allow"),
            description=spec.get("description", ""),
        )
    return out


def _parse_rules(raw_rules: Any) -> tuple[Rule, ...]:
    if raw_rules is None:
        return ()
    if not isinstance(raw_rules, list):
        raise PolicyError("rules must be a list")
    rules: list[Rule] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise PolicyError(f"rule {index} must be a mapping")
        rule_id, rule_type, value = raw.get("id"), raw.get("type"), raw.get("value")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"rule {index} needs a non-empty id")
        if rule_id in seen:
            raise PolicyError(f"duplicate rule id {rule_id}")
        seen.add(rule_id)
        if rule_type not in RULE_TYPES:
            raise PolicyError(f"rule {rule_id}: type must be one of {', '.join(RULE_TYPES)}")
        # An empty value would match every request.
        if not isinstance(value, str) or not value:
            raise PolicyError(f"rule {rule_id}: value must be a non-empty string")
        pattern = None
        if rule_type == "regex":
            try:
                pattern = re.compile(value)
            except re.error:
                raise PolicyError(f"rule {rule_id}: value is not a valid regex") from None
        rules.append(
            Rule(
                id=rule_id,
                type=rule_type,
                value=value,
                pattern=pattern,
                action=raw.get("action", "block"),
                sources=tuple(raw.get("sources") or DEFAULT_RULE_SOURCES),
                severity=raw.get("severity", "high"),
                enabled=raw.get("enabled", True) is not False,
            )
        )
    return tuple(rules)


class PolicyStore:
    """Hands out the current policy, re-reading the file when it changes.

    A file that cannot be read or does not validate never replaces a good
    policy: the last good one stays active and ``last_error`` says why.
    """

    def __init__(self, path: str):
        self._path = path
        self._policy = DEFAULT_POLICY
        # (mtime, size) of the file we last tried, good or bad, so a bad file
        # is not re-parsed on every request. Size is compared as well because
        # modification times can be coarse.
        self._seen: tuple[int, int] | None = None
        self.last_error: str | None = None

    def current(self) -> Policy:
        """Return the active policy. Costs one ``os.stat`` unless the file changed."""
        try:
            stat = os.stat(self._path)
        except OSError as exc:
            self._seen = None
            self.last_error = f"cannot read policy file ({type(exc).__name__})"
            return self._policy

        stamp = (stat.st_mtime_ns, stat.st_size)
        if stamp == self._seen:
            return self._policy
        self._seen = stamp
        try:
            with open(self._path, "rb") as handle:
                self._policy = parse_policy(handle.read())
            self.last_error = None
        except OSError as exc:
            self.last_error = f"cannot read policy file ({type(exc).__name__})"
        except PolicyError as exc:
            self.last_error = f"invalid policy file: {exc}"
        return self._policy
