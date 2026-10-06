"""Catalogue lookup, the governance table, catalogue pricing in the usage row."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
import yaml

from ctrl_ai.core.context import RequestContext
from ctrl_ai.governance.catalogue import parse_models
from ctrl_ai.governance.governance import govern
from ctrl_ai.governance.routes import route_from_authorization
from ctrl_ai.governance.usage import build_usage_row, cost_fields

REPO = Path(__file__).resolve().parents[3]
DOC = yaml.safe_load((REPO / "tests" / "fixtures" / "config" / "models.yaml").read_text())
CAT = parse_models((REPO / "tests" / "fixtures" / "config" / "models.yaml").read_bytes())
TODAY = date(2026, 10, 4)


def catalogue(change=None):
    doc = yaml.safe_load((REPO / "tests" / "fixtures" / "config" / "models.yaml").read_text())
    if change:
        change(doc)
    return parse_models(yaml.safe_dump(doc).encode())


def entry(doc, model_id):
    return next(m for m in doc["models"] if m["id"] == model_id)


def g(model, team="retail-dev", default="chat-groq", data_class="public", cat=CAT, **kw):
    return govern(model, team, default, data_class, cat, today=TODAY, **kw)


def test_lookup_exact_then_longest_wildcard():
    assert CAT.lookup("claude-opus-5-5").id == "claude-opus-5-5"
    assert CAT.lookup("claude-fable-5-1").id == "claude-*"
    assert CAT.lookup("gpt-x") is None
    assert CAT.get("claude-fable-5-1") is None


def test_allowed_model_passes():
    assert g("chat-groq").decision == "allow"


def test_not_in_catalogue_reroutes_to_default_else_refuses():
    r = g("gpt-x")
    assert (r.decision, r.model_routed, r.route_reason) == ("reroute", "chat-groq", "not_approved")
    r = g("gpt-x", default=None)
    assert r.decision == "refuse" and r.rule == "model-not-approved" and "Allowed:" in r.message


def test_banned_reroutes_to_equivalent_else_refuses():
    cat = catalogue(lambda d: entry(d, "chat-mistral").update(status="banned"))
    r = g("chat-mistral", cat=cat)
    assert (r.decision, r.model_routed, r.route_reason) == ("reroute", "chat-groq", "banned")
    cat = catalogue(
        lambda d: (
            entry(d, "claude-haiku-4-5").update(status="banned"),
            entry(d, "claude-haiku-4-5").pop("equivalent", None),
        )
    )
    r = g("claude-haiku-4-5", cat=cat)
    assert (r.decision, r.route_reason, r.rule) == ("refuse", "banned", "model-banned")
    assert "claude-haiku-4-5" not in r.message.split("Allowed:")[1]


def test_deprecated_before_and_after_sunset():
    cat = catalogue(lambda d: entry(d, "claude-opus-5-5").update(status="deprecated", sunset="2026-12-31"))
    r = g("claude-opus-5-5", cat=cat)
    assert r.decision == "allow" and r.flag_reason == "deprecated"
    cat = catalogue(lambda d: entry(d, "claude-opus-5-5").update(status="deprecated", sunset="2026-01-01"))
    r = g("claude-opus-5-5", cat=cat)
    assert (r.decision, r.model_routed, r.route_reason) == ("reroute", "claude-sonnet-5-5", "deprecated")


def test_team_not_allowed_reroutes_to_equivalent_then_default():
    r = g("chat-mistral", team="markets-quant", default="claude-opus-5-5")
    assert (r.decision, r.model_routed, r.route_reason) == ("reroute", "chat-groq", "team_not_allowed")
    cat = catalogue(lambda d: entry(d, "chat-groq").update(teams=["retail-dev"]))
    r = g("chat-mistral", team="markets-quant", default="claude-opus-5-5", cat=cat)
    assert r.model_routed == "claude-opus-5-5"
    r = g("chat-mistral", team="markets-quant", default=None, cat=cat)
    assert (r.decision, r.route_reason) == ("refuse", "team_not_allowed")


def test_admin_may_use_every_model():
    assert g("chat-mistral", team="admin", default=None).decision == "allow"


def test_data_class_reroute_prefers_equivalent_then_capable_model():
    r = g("chat-groq", data_class="confidential")
    assert (r.decision, r.model_routed, r.route_reason) == ("reroute", "claude-opus-5-5", "data_class")
    r = g("claude-sonnet-5-5", data_class="confidential")
    assert r.decision == "allow"
    cat = catalogue(lambda d: [m.update(data_class_max="internal") for m in d["models"]])
    r = g("chat-groq", data_class="confidential", cat=cat)
    assert (r.decision, r.route_reason) == ("refuse", "data_class")


def test_subscription_route_only_reroutes_to_claude():
    r = g("gpt-x", default="chat-groq", subscription=True)
    assert r.decision == "refuse"
    assert all(m.startswith("claude-") for m in r.message.split("Allowed: ")[1].rstrip(".").split(", "))
    r = g("gpt-x", default="claude-sonnet-5-5", subscription=True)
    assert r.model_routed == "claude-sonnet-5-5"


def test_route_from_authorization_prefix():
    assert route_from_authorization("Bearer sk-ant-oat01-x") == "claude_subscription"
    assert route_from_authorization("Bearer sk-ctrl-ai-x") == "external"
    assert route_from_authorization(None) == "external"


def test_catalogue_price_and_shadow():
    c = cost_fields("chat-groq", 1_000_000, 1_000_000, 0.5, CAT)
    assert c == {
        "provider": "groq",
        "price_known": True,
        "cost_usd": pytest.approx(0.375),
        "cost_source": "catalogue",
        "shadow": True,
    }


def test_litellm_cost_then_unknown_then_zero():
    assert cost_fields("claude-fable-5-1", 10, 10, 0.02, CAT)["cost_source"] == "litellm"
    unknown = cost_fields("claude-fable-5-1", 10, 10, None, CAT)
    assert (unknown["price_known"], unknown["cost_usd"], unknown["cost_source"]) == (False, None, "unknown")
    zero = cost_fields("claude-fable-5-1", 0, 0, None, CAT)
    assert (zero["price_known"], zero["cost_usd"]) == (True, 0.0)


def test_usage_row_joins_context_and_detects_fallback():
    slo = {
        "litellm_call_id": "r",
        "status": "success",
        "model_group": "claude-sonnet-5-5",
        "prompt_tokens": 10,
        "completion_tokens": 10,
        "response_cost": 0.1,
        "metadata": {"user_api_key_request_route": "/v1/messages"},
    }
    ctx = RequestContext(request_id="r", model_requested="claude-opus-5-5", model_routed="claude-opus-5-5")
    ctx.masked = {"iban": 1, "pesel": 2}
    row = build_usage_row(slo, ctx, CAT)
    assert row["fallback_used"] is True and row["masked_total"] == 3
    assert row["cost_usd"] == pytest.approx((10 * 2 + 10 * 10) / 1e6)  # priced as the model that answered
