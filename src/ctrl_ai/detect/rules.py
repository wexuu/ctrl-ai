"""Match text against the policy's rules and the enabled rule packs."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ctrl_ai.core.context import Finding, Piece
from ctrl_ai.core.policy import Policy, Rule
from ctrl_ai.detect.detectors import Scans
from ctrl_ai.detect.packs import BUILTIN_RULES, SECRETS, SIGNATURES, pack_rules

# Claude Code's <system-reminder> content is checked only by these packs.
REMINDER_PACKS = (SECRETS, SIGNATURES)


def _rule_matches(rule: Rule, text: str) -> bool:
    if rule.type == "contains":
        return rule.value in text
    return (rule.pattern or re.compile(rule.value)).search(text) is not None


def all_matches(
    policy: Policy, pieces: Iterable[Piece], feed=None, scans: Scans | None = None
) -> list[Finding]:
    """Every rule that matched, one finding per (rule, source).

    Order: policy rules (file order), then enabled packs, then signatures. A policy rule
    with the id of a pack rule overrides that pack rule instead of running on its own.
    """
    pieces = [p for p in pieces if p.text]
    scans = scans if scans is not None else Scans()
    packs = pack_rules(policy.rule_packs, feed)
    pack_ids = {r.id for r in packs}
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(rule_id: str, pack: str, source: str, action: str, severity: str) -> None:
        if (rule_id, source) not in seen:
            seen.add((rule_id, source))
            findings.append(Finding(rule_id, pack, source, action, severity))

    for rule in policy.rules:
        if rule.id in pack_ids or not rule.enabled:
            continue
        for piece in pieces:
            if piece.reminder or piece.source not in rule.sources:
                continue
            if _rule_matches(rule, piece.text):
                add(rule.id, "policy", piece.source, rule.action, rule.severity)

    for prule in packs:
        override = policy.rule_override(prule.id)
        if override is not None and not override.enabled:
            continue
        action = override.action if override is not None else prule.action
        severity = override.severity if override is not None else prule.severity
        sources = override.sources if override is not None else prule.sources
        for piece in pieces:
            if piece.source not in sources:
                continue
            if piece.reminder and prule.pack not in REMINDER_PACKS:
                continue
            if prule.entity is not None:
                # Identifier rules read the piece's one detection pass (overlaps resolved).
                hit = any(m.entity == prule.entity for m in scans.matches(piece.text))
            else:
                hit = prule.matches(piece.text)
            if hit:
                add(prule.id, prule.pack, piece.source, action, severity)
    return findings


def data_class(findings: Iterable[Finding]) -> str:
    """The highest data class the findings imply: a built-in rule's own class (payment and
    national identifiers and secrets are confidential), internal for any other finding, else
    public."""
    level = "public"
    for f in findings:
        rule = BUILTIN_RULES.get(f.rule)
        if rule is not None and rule.data_class == "confidential":
            return "confidential"
        level = "internal"
    return level
