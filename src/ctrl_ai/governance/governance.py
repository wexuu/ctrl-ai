"""Model governance: which model a team may use, for which data. Pure.

Reroutes rather than refuses where it can. The first situation that applies wins:
not in the catalogue, banned, deprecated, team not allowed, data class too high.
A request on a forwarded Claude subscription may only be routed to another Claude model.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import TypeGuard

from ctrl_ai.governance.catalogue import DATA_CLASS_LEVEL, Catalogue, ModelEntry

ADMIN_TEAM = "admin"
RULE_IDS = {
    "not_approved": "model-not-approved",
    "banned": "model-banned",
    "deprecated": "model-deprecated",
    "team_not_allowed": "model-team-not-allowed",
    "data_class": "model-data-class",
    "subscription": "model-subscription-only-claude",
}


@dataclass(frozen=True)
class GovernanceResult:
    decision: str  # allow | reroute | refuse
    model_routed: str | None
    route_reason: str | None = None
    message: str | None = None
    flag_reason: str | None = None  # allowed but flagged (deprecated before sunset)

    @property
    def rule(self) -> str | None:
        return RULE_IDS.get(self.route_reason or "") if self.decision == "refuse" else None


def _usable(entry: ModelEntry | None, team: str | None, today: date) -> bool:
    if entry is None or entry.wildcard or entry.status == "banned":
        return False
    if entry.status == "deprecated" and entry.past_sunset(today):
        return False
    return team == ADMIN_TEAM or entry.allows_team(team)


def allowed_models(
    catalogue: Catalogue, team: str | None, today: date, claude_only: bool = False
) -> list[str]:
    return [
        e.id
        for e in catalogue.models
        if _usable(e, team, today) and (not claude_only or e.id.startswith("claude-"))
    ]


def govern(
    model: str | None,
    team: str | None,
    default_model: str | None,
    data_class_detected: str,
    catalogue: Catalogue,
    *,
    subscription: bool = False,
    today: date | None = None,
) -> GovernanceResult:
    today = today or date.today()
    if not catalogue.loaded or not model:
        return GovernanceResult("allow", model)

    def ok_target(target: str | None) -> TypeGuard[str]:
        if not target or (subscription and not target.startswith("claude-")):
            return False
        return _usable(catalogue.get(target), team, today)

    def refuse(reason: str, extra: str = "") -> GovernanceResult:
        allowed = allowed_models(catalogue, team, today, claude_only=subscription)
        text = (
            f"ctrl-ai: model {model} is not approved for team {team}{extra}. "
            f"Allowed: {', '.join(allowed) or 'none'}."
        )
        return GovernanceResult("refuse", model, reason, text)

    def reroute(target: str, reason: str) -> GovernanceResult:
        return GovernanceResult("reroute", target, reason)

    entry = catalogue.lookup(model)
    if entry is None:
        if ok_target(default_model):
            return reroute(default_model, "not_approved")
        return refuse("not_approved")
    if entry.status == "banned":
        if ok_target(entry.equivalent):
            return reroute(entry.equivalent, "banned")
        return refuse("banned")
    flag_reason = None
    if entry.status == "deprecated":
        if entry.past_sunset(today):
            if ok_target(entry.equivalent):
                return reroute(entry.equivalent, "deprecated")
            return refuse("deprecated")
        flag_reason = "deprecated"
    if team != ADMIN_TEAM and not entry.allows_team(team):
        for target in (entry.equivalent, default_model):
            if ok_target(target):
                return reroute(target, "team_not_allowed")
        return refuse("team_not_allowed")
    needed = DATA_CLASS_LEVEL.get(data_class_detected, 0)
    if needed > DATA_CLASS_LEVEL.get(entry.data_class_max, 0):
        candidates = [entry.equivalent] + [e.id for e in catalogue.models]
        for target in candidates:
            target_entry = catalogue.get(target) if target else None
            if (
                ok_target(target)
                and target_entry is not None
                and DATA_CLASS_LEVEL.get(target_entry.data_class_max, 0) >= needed
            ):
                return reroute(target, "data_class")
        return refuse("data_class", f" with {data_class_detected} data")
    return GovernanceResult("allow", model, flag_reason=flag_reason)
