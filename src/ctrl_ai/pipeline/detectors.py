"""Detectors: find things in the newest turn and say nothing about what to do.

Pure functions over pieces and a policy. They produce normalised pieces, findings and the
texts the semantic check will see; the evaluator turns those into a decision.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ctrl_ai.core.context import Finding, Piece
from ctrl_ai.core.policy import Policy
from ctrl_ai.detect.normalise import merge_stats, normalise
from ctrl_ai.detect.rules import all_matches

NO_NORMALISATION = {"hidden_chars": 0, "tag_chars_decoded": False, "changed": False}


@dataclass
class Detection:
    """What the deterministic detectors found in one request."""

    pieces: list[Piece]  # the checked pieces, normalised
    findings: list[Finding]
    normalisation: dict


def normalise_pieces(
    pieces: Iterable[Piece], policy: Policy, *, block_hidden: bool
) -> tuple[list[Piece], dict, Finding | None]:
    """Normalise every piece; hidden characters above the policy's threshold become a finding."""
    pieces = list(pieces)
    if not policy.normalisation_enabled:
        return pieces, dict(NO_NORMALISATION), None
    stats, out = [], []
    worst_source, worst = None, 0
    for piece in pieces:
        clean, st = normalise(piece.text)
        stats.append(st)
        if st["hidden_chars"] > worst:
            worst_source, worst = piece.source, st["hidden_chars"]
        out.append(piece if clean is piece.text else Piece(clean, piece.source, piece.reminder))
    merged = merge_stats(stats)
    finding = None
    if merged["hidden_chars"] >= policy.hidden_char_threshold:
        action = "block" if block_hidden else "flag"
        finding = Finding("hidden-characters", "normalisation", worst_source or "prompt", action, "high")
    return out, merged, finding


def detect(pieces: Iterable[Piece], policy: Policy, feed, *, block_hidden: bool) -> Detection:
    """Normalisation, then the policy's rules, the rule packs and the signature feed.

    ``block_hidden`` says whether a hidden-character finding blocks (strict profiles) or flags.
    Pack findings for personal and national identifiers carry the action ``mask``; the evaluator decides whether
    the request is actually rewritten.
    """
    pieces, stats, hidden = normalise_pieces(pieces, policy, block_hidden=block_hidden)
    findings = all_matches(policy, pieces, feed)
    if hidden is not None:
        findings.append(hidden)
    return Detection(pieces, findings, stats)


def semantic_texts(pieces: Iterable[Piece], policy: Policy) -> dict[str, str]:
    """One text per source for Jev and the judge: prompt and tool_result, never reminders."""
    pieces = list(pieces)
    out: dict[str, str] = {}
    for source in ("prompt", "tool_result"):
        if source not in policy.jev_sources:
            continue
        text = "\n".join(p.text for p in pieces if p.source == source and not p.reminder)
        if text:
            out[source] = text
    return out
