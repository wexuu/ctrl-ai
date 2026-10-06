"""Shared test helpers for the deterministic half of the engine."""

from __future__ import annotations

from ctrl_ai.core.context import RequestContext
from ctrl_ai.core.policy import Policy
from ctrl_ai.pipeline import detectors, evaluator


def check_pieces(ctx: RequestContext, policy: Policy, feed=None) -> None:
    """The detectors over ``ctx.pieces``, then the block or flag decision, as the engine runs them."""
    found = detectors.detect(ctx.pieces, policy, feed, block_hidden=ctx.profile.semantic_action == "block")
    ctx.pieces, ctx.findings, ctx.normalisation = found.pieces, found.findings, found.normalisation
    evaluator.apply_findings(ctx)
