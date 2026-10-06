"""Built-in rule packs and their registry.

``pii`` (identifiers any organisation handles: e-mail, phone, card, IBAN), ``pl`` (Polish
national identifiers: PESEL, NIP, NRB account), ``secrets`` (keys and tokens) and
``signatures`` (the known-exploit feed). A policy switches packs on with ``rule_packs``.

The rule ids are fixed so the admin panel can list them. A policy ``rules:`` entry with the
same id overrides a pack rule's ``action``, ``enabled``, ``severity`` and ``sources``; the
pack's detector stays. ``PACKS`` is the one registry the policy schema, the admin panel, the
dashboard and the masking plan read.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from ctrl_ai.detect import detectors

PII = "pii"
PL = "pl"
SECRETS = "secrets"
SIGNATURES = "signatures"
ALL_SOURCES = ("prompt", "tool_result", "tool_call")


@dataclass(frozen=True)
class PackRule:
    id: str
    pack: str
    action: str
    severity: str
    sources: tuple[str, ...]
    matches: Callable[[str], bool]
    entity: str | None = None  # the detector entity masking rewrites, for identifier rules
    data_class: str = "confidential"  # the data class a finding of this rule implies


def _detector(entity: str) -> Callable[[str], bool]:
    # detect() resolves overlaps (an NRB inside an IBAN is the IBAN) and is cached per text,
    # so all identifier rules share one pass over each piece.
    return lambda text: any(m.entity == entity for m in detectors.detect(text, (entity,)))


def _regex(pattern: str, needles: tuple[str, ...] = ()) -> Callable[[str], bool]:
    """A regex test, optionally behind a cheap substring prefilter (a leading \\b or (?i) makes
    Python's re try every position, which is slow on long texts)."""
    compiled = re.compile(pattern)
    if needles:
        return lambda text: any(n in text for n in needles) and compiled.search(text) is not None
    return lambda text: compiled.search(text) is not None


def _cased(*words: str) -> tuple[str, ...]:
    return tuple({v for w in words for v in (w, w.upper(), w.capitalize())})


def _identifier(
    rule_id: str, pack: str, entity: str, severity: str = "high", data_class: str = "confidential"
):
    return PackRule(rule_id, pack, "mask", severity, ALL_SOURCES, _detector(entity), entity, data_class)


# Contact details are personal data but common in ordinary work, so they mark a request internal;
# payment and national identifiers mark it confidential.
PII_RULES = (
    _identifier("pii-email", PII, "email", "medium", "internal"),
    _identifier("pii-phone", PII, "phone", "medium", "internal"),
    _identifier("pii-card", PII, "card"),
    _identifier("pii-iban", PII, "iban"),
)
PL_RULES = (
    _identifier("pl-pesel", PL, "pesel"),
    _identifier("pl-nip", PL, "nip"),
    _identifier("pl-account", PL, "account_pl"),
)

_SECRET_SOURCES = ("prompt", "tool_result")
SECRET_RULES = (
    PackRule(
        "secret-aws-key",
        SECRETS,
        "block",
        "critical",
        _SECRET_SOURCES,
        _regex(r"(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    PackRule(
        "secret-private-key",
        SECRETS,
        "block",
        "critical",
        _SECRET_SOURCES,
        _regex(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
    ),
    PackRule(
        "secret-github-token",
        SECRETS,
        "block",
        "critical",
        _SECRET_SOURCES,
        _regex(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|github_pat_[A-Za-z0-9_]{60,}\b"),
    ),
    PackRule(
        "secret-generic-api-key",
        SECRETS,
        "block",
        "critical",
        _SECRET_SOURCES,
        _regex(
            r"(?i)\b(api[_-]?key|secret|access[_-]?token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{24,}",
            _cased("api", "secret", "token"),
        ),
    ),
    PackRule(
        "secret-jwt",
        SECRETS,
        "block",
        "critical",
        _SECRET_SOURCES,
        _regex(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ),
    PackRule(
        "secret-password-assignment",
        SECRETS,
        "block",
        "critical",
        _SECRET_SOURCES,
        _regex(r"(?i)\bpass(word|wd)?\b\s*[:=]\s*\S{6,}", _cased("pass")),
    ),
)


@dataclass(frozen=True)
class Pack:
    id: str
    label: str
    rules: tuple[PackRule, ...]  # empty for signatures: those come from the feed


PACKS: dict[str, Pack] = {
    p.id: p
    for p in (
        Pack(PII, "personal data (e-mail, phone, payment card, IBAN)", PII_RULES),
        Pack(PL, "Polish national identifiers (PESEL, NIP, NRB account)", PL_RULES),
        Pack(SECRETS, "secrets (cloud keys, private keys, tokens, passwords)", SECRET_RULES),
        Pack(SIGNATURES, "known-exploit signatures (the signature feed)", ()),
    )
}
PACK_IDS = tuple(PACKS)
# Every built-in rule by id, and what masking and the data class need from it.
BUILTIN_RULES: dict[str, PackRule] = {r.id: r for p in PACKS.values() for r in p.rules}
RULE_ENTITY = {r.id: r.entity for r in BUILTIN_RULES.values() if r.entity}


def rule_ids(pack_id: str) -> tuple[str, ...]:
    """The built-in rule ids of a pack (none for signatures, whose ids come from the feed)."""
    pack = PACKS.get(pack_id)
    return tuple(r.id for r in pack.rules) if pack else ()


# Substring prefilters for feed entries whose pattern is slow to scan (case-insensitive with a
# leading \b). Only a speed-up: an id that is not listed is matched by its pattern alone.
SIGNATURE_NEEDLES = {"sig-hidden-instruction": _cased("ignore", "disregard")}


def _signature_matcher(sig) -> Callable[[str], bool]:
    needles = SIGNATURE_NEEDLES.get(sig.id, ())
    pattern = sig.pattern
    if needles:
        return lambda text: any(n in text for n in needles) and pattern.search(text) is not None
    return lambda text: pattern.search(text) is not None


def signature_rules(feed) -> tuple[PackRule, ...]:
    return tuple(
        PackRule(s.id, SIGNATURES, s.action, s.severity, s.applies_to, _signature_matcher(s))
        for s in feed.signatures
    )


def pack_rules(enabled_packs, feed=None) -> tuple[PackRule, ...]:
    """The pack rules switched on by the policy, in the order packs → signatures."""
    out: list[PackRule] = []
    for pack in PACKS.values():
        if pack.id in enabled_packs:
            out.extend(pack.rules)
    if SIGNATURES in enabled_packs and feed is not None:
        out.extend(signature_rules(feed))
    return tuple(out)
