"""The deployable configuration in config/ and its profiles parse and match their JSON Schemas.

Every other test runs against the frozen copies in tests/fixtures/config; this is the one place
that reads the shipped files. It asserts nothing about their values beyond consistency: the teams
that the model catalogue and the MCP servers name exist in the same configuration.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ctrl_ai.core.policy import parse_policy
from ctrl_ai.core.schema import validate
from ctrl_ai.detect.packs import PACK_IDS
from ctrl_ai.detect.signatures import parse_feed
from ctrl_ai.governance.catalogue import parse_models
from ctrl_ai.governance.identity import parse_teams

REPO = Path(__file__).resolve().parents[3]
FILES = {
    "policy": parse_policy,
    "teams": parse_teams,
    "models": parse_models,
    "signatures": parse_feed,
    "mcp": None,
}
PROFILES = sorted(
    p.relative_to(REPO).as_posix() for p in (REPO / "config" / "profiles").iterdir() if p.is_dir()
)
DIRECTORIES = ["config", "tests/fixtures/config", *PROFILES]


def config_file(directory: str, name: str) -> Path:
    """A profile holds only the files that differ from config/; the rest come from there."""
    path = REPO / directory / f"{name}.yaml"
    return path if path.exists() else REPO / "config" / f"{name}.yaml"


def load(directory: str, name: str) -> dict:
    return yaml.safe_load(config_file(directory, name).read_bytes())


@pytest.mark.parametrize("name", sorted(FILES))
@pytest.mark.parametrize("directory", DIRECTORIES)
def test_config_file_parses_and_matches_its_schema(directory, name):
    raw = config_file(directory, name).read_bytes()
    validate(yaml.safe_load(raw), name)
    parser = FILES[name]
    if parser is not None:
        parser(raw)


def test_the_bank_profile_exists_and_uses_every_pack():
    assert "config/profiles/bank" in PROFILES
    assert set(load("config/profiles/bank", "policy")["rule_packs"]) == set(PACK_IDS)


@pytest.mark.parametrize("directory", DIRECTORIES)
def test_named_teams_exist(directory):
    teams = {t["id"] for t in load(directory, "teams")["teams"]}
    named = {t for m in load(directory, "models")["models"] for t in m.get("teams", []) if t != "*"}
    named |= {t for s in load(directory, "mcp")["servers"] for t in s.get("teams", []) if t != "*"}
    named |= {t["owner"] for t in load(directory, "models")["models"] if t.get("owner")}
    assert named <= teams, named - teams


def test_degraded_lane_policy_parses_and_matches_its_schema():
    raw = (REPO / "deploy" / "lane" / "policy.lane.yaml").read_bytes()
    validate(yaml.safe_load(raw), "policy")
    parse_policy(raw)
