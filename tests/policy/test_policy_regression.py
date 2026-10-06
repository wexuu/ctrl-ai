"""Policy regression: a request in, the decision out, against the frozen test configuration.

Each case in cases.yaml names a team (none means the master key), gives a prompt or a full
message list, optional stub verdicts for Jev and the judge, and the fields of the decision row
it expects. The engine runs with the frozen policy, teams and catalogue; no network, no Redis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from ctrl_ai.core.audit import AuditLog
from ctrl_ai.core.context import ADMIN_IDENTITY, Identity
from ctrl_ai.core.filestore import FileStore
from ctrl_ai.core.policy import PolicyStore
from ctrl_ai.detect.signatures import EMPTY_FEED, parse_feed
from ctrl_ai.governance.catalogue import EMPTY_CATALOGUE, parse_models
from ctrl_ai.governance.identity import EMPTY_TEAMS, parse_teams
from ctrl_ai.pipeline.engine import Engine
from ctrl_ai.semantic.models import StaticModel

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "fixtures" / "config"
CASES: list[dict] = yaml.safe_load((HERE / "cases.yaml").read_text(encoding="utf-8"))
TEAMS = parse_teams((FIXTURES / "teams.yaml").read_bytes())


def jev_stub(score: float | str) -> StaticModel:
    if score == "unavailable":
        return StaticModel(status="unavailable", name="jev-test", error="timeout")
    answers = {"instruction_override": float(score), "harmful_misuse": 0.0}
    return StaticModel(float(score), name="jev-test", answers=answers)


def judge_stub(score: float | str) -> StaticModel:
    if score == "unavailable":
        return StaticModel(status="unavailable", name="judge-test", error="timeout")
    return StaticModel(float(score), name="judge-test", category="instruction_override", reason="stub judge")


def identity_for(team: str | None) -> Identity:
    if team is None:
        return ADMIN_IDENTITY
    entry = TEAMS.get(team)
    assert entry is not None, f"unknown team in cases.yaml: {team}"
    return Identity(
        team=entry.id,
        department=entry.department,
        user="tester",
        key_id="k_test0001",
        profile=entry.profile,
        mode=entry.mode,
    )


def request_body(case: dict) -> dict:
    messages = case.get("messages") or [{"role": "user", "content": case["prompt"]}]
    return {"model": case.get("model", "claude-sonnet-5-5"), "max_tokens": 64, "messages": messages}


def lookup(row: dict, dotted: str) -> Any:
    current: Any = row
    for part in dotted.split("."):
        current = current.get(part) if isinstance(current, dict) else None
    return current


def engine_for(tmp_path: Path) -> Engine:
    return Engine(
        policy_store=PolicyStore(str(FIXTURES / "policy.yaml")),
        audit=AuditLog(str(tmp_path / "audit.jsonl")),
        teams=FileStore(str(FIXTURES / "teams.yaml"), parse_teams, EMPTY_TEAMS),
        catalogue=FileStore(str(FIXTURES / "models.yaml"), parse_models, EMPTY_CATALOGUE),
        signatures=FileStore(str(FIXTURES / "signatures.yaml"), parse_feed, EMPTY_FEED),
        masking_secret="ctrl-ai-test-masking-secret",
    )


async def run_case(case: dict, tmp_path: Path) -> dict:
    decision = await engine_for(tmp_path).evaluate(
        request_body(case),
        call_type="anthropic_messages",
        request_id="regression",
        classifier=jev_stub(case.get("jev", 0.02)),
        judge=judge_stub(case.get("judge", 0.05)),
        identity=identity_for(case.get("team")),
        route=case.get("route"),
    )
    row = dict(decision.row)
    row["finding_rules"] = sorted(f["rule"] for f in row.get("findings") or [])
    row["message"] = decision.message
    return row


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
async def test_decision(case: dict, tmp_path: Path):
    row = await run_case(case, tmp_path)
    actual = {key: lookup(row, key) for key in case["expect"]}
    assert actual == case["expect"]
