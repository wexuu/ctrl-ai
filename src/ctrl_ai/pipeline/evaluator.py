"""The evaluator: from findings, profile and shared state to a decision.

Nothing here calls out or changes the request. Each function reads what the detectors and the
stores produced and sets the decision fields of the ``RequestContext``: ``decision``, ``rule``,
``would_block``, ``flagged``, the refusal text and status code.
"""

from __future__ import annotations

from dataclasses import replace

from ctrl_ai.core.context import Finding, RequestContext
from ctrl_ai.core.policy import Policy
from ctrl_ai.core.scores import Score
from ctrl_ai.detect import masking
from ctrl_ai.detect.packs import RULE_ENTITY
from ctrl_ai.detect.rules import data_class
from ctrl_ai.governance import budgets, loops
from ctrl_ai.governance.catalogue import Catalogue
from ctrl_ai.governance.governance import govern
from ctrl_ai.governance.identity import Teams
from ctrl_ai.semantic.outage import FAIL_CLOSED_MESSAGE


def block_message(rule_id: str) -> str:
    return f"Blocked by ctrl-ai: rule {rule_id}. Remove the flagged content and try again."


def relaxed(ctx: RequestContext, control: str) -> bool:
    """True when a valid break-glass override relaxes this control."""
    return control in ((ctx.break_glass or {}).get("relaxed") or [])


def with_action(finding: Finding, action: str) -> Finding:
    return replace(finding, action=action)


# ---------------------------------------------------------------- findings


def relax_findings(ctx: RequestContext) -> None:
    """A break-glass override turns the blocking findings it names into flags."""
    relax = set((ctx.break_glass or {}).get("relaxed") or [])
    if not relax:
        return
    ctx.findings = [
        with_action(f, "flag")
        if f.action == "block" and (f.rule in relax or f.pack in relax) and f.rule not in ctx.never_relax
        else f
        for f in ctx.findings
    ]


def apply_findings(ctx: RequestContext) -> None:
    """Block, flag or record, from the findings and the effective mode."""
    relax_findings(ctx)
    ctx.data_class_detected = data_class(ctx.findings)
    blocking = [f for f in ctx.findings if f.action == "block"]
    if any(f.action in ("flag", "mask") for f in ctx.findings):
        ctx.flagged = True
    if blocking:
        ctx.rule = blocking[0].rule
        ctx.would_block = True
        if ctx.mode == "enforce":
            ctx.decision = "block"
            ctx.message = block_message(blocking[0].rule)
        else:
            ctx.flagged = True


# ---------------------------------------------------------------- masking plan


def plan_masking(ctx: RequestContext, policy: Policy, *, has_secret: bool) -> None:
    """Decide what masking does for this request; set the identifier findings' action accordingly.

    External route with ``mask``: the forwarded request is rewritten (findings say ``mask``).
    Claude subscription: never rewritten, only the semantic copy is masked (findings ``flag``).
    """
    settings = policy.masking
    plan = None
    if settings.get("enabled"):
        if not has_secret:
            ctx.masking = "no_secret"
        elif ctx.route == "claude_subscription":
            plan = "semantic_only" if settings["routes"].get("claude_subscription") != "off" else None
        elif settings["routes"].get("external") == "mask":
            plan = "rewrite"
        else:
            plan = "semantic_only"
    ctx.mask_plan = plan
    entities = set(masking.detector_entities(settings.get("entities") or ()))
    ctx.findings = [
        with_action(f, "flag")
        if f.action == "mask" and not (plan == "rewrite" and RULE_ENTITY.get(f.rule) in entities)
        else f
        for f in ctx.findings
    ]
    if plan == "rewrite" and ctx.stream and ctx.endpoint != "chat_completions":
        ctx.restore = "unsupported_stream"


# ---------------------------------------------------------------- model governance


def governance_data_class(ctx: RequestContext) -> str:
    """The data class that decides model eligibility: what actually leaves.

    Findings that are masked before the request leaves do not count.
    """
    return data_class(f for f in ctx.findings if f.action != "mask")


def apply_governance(ctx: RequestContext, teams: Teams, catalogue: Catalogue) -> None:
    """Model governance: reroute or refuse; a monitor profile only records it."""
    team = teams.get(ctx.identity.team)
    result = govern(
        ctx.model_requested,
        ctx.identity.team,
        team.default_model if team else None,
        governance_data_class(ctx),
        catalogue,
        subscription=ctx.route == "claude_subscription",
    )
    if result.flag_reason:
        ctx.flagged = True
    if result.decision == "allow":
        return
    ctx.route_reason = result.route_reason
    if ctx.mode != "enforce":
        ctx.flagged = True
        if result.decision == "refuse":
            ctx.would_block = True
            ctx.rule = ctx.rule or result.rule
        return
    if result.decision == "reroute":
        ctx.model_routed = result.model_routed
        ctx.decision = "reroute"
    else:
        ctx.decision = "block"
        ctx.would_block = True
        ctx.rule = result.rule
        ctx.status_code = 403
        ctx.message = result.message


# ---------------------------------------------------------------- semantic outage


def apply_outage(ctx: RequestContext, policy: Policy, status: dict, judge_model: str | None) -> None:
    """Semantic outage: skip the classifier and the judge; degrade (allow, flag) or fail closed (503)."""
    if not status["outage"]:
        return
    ctx.outage = status
    ctx.jev = Score.unavailable("circuit_open")
    ctx.judge = Score.unavailable("circuit_open", model=judge_model)
    settings = policy.semantic_outage
    closed = status["mode"] == "fail_closed" or (
        settings.get("strict_profiles_fail_closed") and ctx.profile.on_semantic_unavailable == "block"
    )
    ctx.flagged = True
    if closed and ctx.mode == "enforce":
        ctx.semantic = {"source": None, "score": None, "action": "block", "reason": "outage"}
        ctx.decision = "block"
        ctx.would_block = True
        ctx.rule = "semantic-outage"
        ctx.status_code = 503
        ctx.message = FAIL_CLOSED_MESSAGE
    else:
        ctx.semantic = {"source": None, "score": None, "action": "flag", "reason": "outage"}


# ---------------------------------------------------------------- loop caps and budgets


def apply_loop(ctx: RequestContext, loop: dict | None) -> None:
    """Loop caps: warn flags; throttle and stop refuse with 429 and Retry-After."""
    ctx.loop = loop
    if not loop or loop["state"] == "unavailable":
        return
    ctx.flagged = True
    if loop["state"] == "warn":
        return
    if relaxed(ctx, "loops") or ctx.mode != "enforce":
        ctx.would_block = ctx.mode != "enforce" or ctx.would_block
        return
    ctx.decision = "throttle"
    ctx.status_code = 429
    ctx.headers = {"Retry-After": "30"}
    ctx.message = loops.message(loop)


def budget_action(ctx: RequestContext, record: dict) -> str | None:
    """What an admission record means for this request: None (go on), ``downgrade`` or ``block``.

    Sets the flag for a budget that is near or over its limit; alert-only budgets, a break-glass
    override and monitor mode never refuse.
    """
    if record["state"] == "near":
        ctx.flagged = True
        return None
    if record["state"] != "exceeded":
        return None
    ctx.flagged = True
    action = record["action"]
    if action == "alert_only" or relaxed(ctx, "budget") or ctx.mode != "enforce":
        return None
    return "downgrade" if action == "downgrade" else "block"


def refuse_over_budget(ctx: RequestContext, team_id: str, record: dict) -> None:
    ctx.decision = "block"
    ctx.would_block = True
    ctx.rule = "budget-exceeded"
    ctx.status_code = 429
    ctx.message = budgets.block_message(team_id, record.get("used_usd"), record.get("limit_usd"))
