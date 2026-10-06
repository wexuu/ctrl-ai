"""The engine: one request through the detectors, the evaluator and the effects, then the row.

The gateway runs the two halves in separate LiteLLM hooks: ``pre_call`` (deterministic, before
the model call) and ``semantic_call`` (the classifier and the judge, alongside the model call).
``evaluate`` runs both for tests and as the reference. Every collaborator is passed in;
``pipeline/runtime.py`` builds the production engine from ``Settings``.

The engine fails open: an unexpected error results in ``allow`` and a row carrying an ``error``
field. Neither the row nor any error text ever contains the user's text.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import Any

from ctrl_ai.core.audit import AuditLog
from ctrl_ai.core.context import Identity, Piece, RequestContext
from ctrl_ai.core.filestore import StaticStore, Store
from ctrl_ai.core.policy import Policy, PolicyStore
from ctrl_ai.core.rows import break_glass_row, decision_row
from ctrl_ai.core.scores import Score
from ctrl_ai.core.state import RedisState
from ctrl_ai.detect import masking
from ctrl_ai.detect.extract import (
    detect_endpoint,
    is_claude_code,
    latest_prompt_text,
    newest_pieces,
    session_header,
    tool_call_signature,
)
from ctrl_ai.detect.signatures import EMPTY_FEED, Feed
from ctrl_ai.governance import breakglass, budgets, loops
from ctrl_ai.governance.catalogue import EMPTY_CATALOGUE, Catalogue
from ctrl_ai.governance.governance import govern
from ctrl_ai.governance.identity import EMPTY_TEAMS, Teams
from ctrl_ai.governance.routes import route_of
from ctrl_ai.pipeline import detectors, effects, evaluator
from ctrl_ai.pipeline.ctxcache import ContextCache
from ctrl_ai.semantic import semantic, shadow
from ctrl_ai.semantic.models import DecisionModel
from ctrl_ai.semantic.outage import OutageMonitor

DEFAULT_CLASSIFIER_TIMEOUT_S = 2.0
# The classifier enforces its own timeout; ours is a backstop slightly behind it.
CLASSIFIER_TIMEOUT_MARGIN_S = 0.5
EMPTY_REGISTER: dict = {"overrides": []}


@dataclass
class Decision:
    decision: str  # allow | block | reroute | throttle
    rule: str | None
    would_block: bool
    message: str | None  # text for the client when blocked
    row: dict  # the decision row that was written
    ctx: RequestContext | None = None


class Engine:
    """The decision pipeline with its collaborators.

    Only ``policy_store`` and ``audit`` are required; everything else defaults to an inert
    stand-in (no teams, no catalogue, no signature feed, no shared state, no decision models),
    which is what unit tests want and what the production runtime overrides.
    """

    def __init__(
        self,
        *,
        policy_store: PolicyStore,
        audit: AuditLog,
        state: RedisState | None = None,
        teams: Store[Teams] | None = None,
        catalogue: Store[Catalogue] | None = None,
        signatures: Store[Feed] | None = None,
        break_glass_register: Store[dict] | None = None,
        outage: OutageMonitor | None = None,
        cache: ContextCache | None = None,
        classifier: DecisionModel | None = None,
        judge: DecisionModel | None = None,
        shadow: DecisionModel | None = None,
        masking_secret: str = "",
        break_glass_secret: str = "",
        classifier_timeout_s: float = DEFAULT_CLASSIFIER_TIMEOUT_S,
        clock: Callable[[], float] = time.time,
    ):
        self.policy_store = policy_store
        self.audit = audit
        self.state = state if state is not None else RedisState("")
        self.teams: Store[Teams] = teams if teams is not None else StaticStore(EMPTY_TEAMS)
        self.catalogue: Store[Catalogue] = (
            catalogue if catalogue is not None else StaticStore(EMPTY_CATALOGUE)
        )
        self.signatures: Store[Feed] = signatures if signatures is not None else StaticStore(EMPTY_FEED)
        self.break_glass_register: Store[dict] = (
            break_glass_register if break_glass_register is not None else StaticStore(EMPTY_REGISTER)
        )
        self.outage = outage or OutageMonitor(write=audit.write, register=self.break_glass_register)
        self.cache = cache or ContextCache()
        self.classifier = classifier
        self.judge = judge
        self.shadow = shadow
        self.masking_secret = masking_secret
        self.break_glass_secret = break_glass_secret
        self.classifier_timeout_s = classifier_timeout_s
        self.clock = clock
        self.break_glass_uses = breakglass.UseTracker()

    # ------------------------------------------------------------------ the two halves

    async def evaluate(
        self,
        data: dict,
        *,
        call_type: str | None = None,
        request_id: str | None = None,
        identity: Identity | None = None,
        route: str | None = None,
        classifier: DecisionModel | None = None,
        judge: DecisionModel | None = None,
    ) -> Decision:
        """Decide whether a request may go to the model, and write the decision row.

        Reads only named fields of ``data``; the rest of that dictionary holds credentials.
        """
        ctx = await self.pre_call(
            data, call_type=call_type, request_id=request_id, identity=identity, route=route
        )
        if ctx.decision != "block":
            await self.semantic_call(ctx, classifier=classifier, judge=judge)
        return self.finish(ctx)

    async def pre_call(
        self,
        data: dict,
        *,
        call_type: str | None = None,
        request_id: str | None = None,
        identity: Identity | None = None,
        route: str | None = None,
    ) -> RequestContext:
        """The deterministic half: extract, detect, evaluate, and rewrite what masking rewrites."""
        started = time.perf_counter()
        ctx = RequestContext(request_id=request_id)
        if identity is not None:
            ctx.identity = identity
        ctx.route_hint = route or None
        try:
            policy = self._deterministic(data, call_type, ctx)
            ctx.policy = policy
            if ctx.decision != "block" and policy.schema_version == 2:
                status = self.outage.status(policy.semantic_outage)
                evaluator.apply_outage(ctx, policy, status, self.judge.name if self.judge else None)
            if ctx.decision != "block" and policy.schema_version == 2 and policy.loops.get("enabled"):
                effects.cap_timeout(data, policy)
                evaluator.apply_loop(ctx, await self._check_loop(ctx, data, policy))
            if ctx.decision not in ("block", "throttle"):
                await self._apply_budget(ctx, data)
            if ctx.decision not in ("block", "throttle") and ctx.mask_plan == "rewrite":
                await effects.rewrite_request(
                    ctx, data, policy, self._masker(ctx, policy), self.state, self.masking_secret
                )
        except Exception as exc:
            self._fail_open(ctx, exc)
        ctx.guard_ms = round((time.perf_counter() - started) * 1000, 1)
        return ctx

    async def semantic_call(
        self,
        ctx: RequestContext,
        *,
        classifier: DecisionModel | None = None,
        judge: DecisionModel | None = None,
    ) -> RequestContext:
        """The semantic half: the classifier, the judge, the profile's decision. Never raises.

        ``classifier`` and ``judge`` replace the engine's own models for this call.
        """
        started = time.perf_counter()
        try:
            policy = ctx.policy
            if policy is None or ctx.decision == "block" or ctx.outage:
                return ctx
            model = classifier or self.classifier
            judge_model = judge or self.judge

            async def ask(texts: dict[str, str]) -> Score:
                return await self.ask_classifier(model, texts)

            classifier_call: semantic.ClassifierCheck = ask
            judge_call: semantic.JudgeCheck | None = judge_model.score if judge_model is not None else None
            if policy.schema_version == 2:
                if model is not None:  # an absent classifier is not an outage
                    classifier_call = self._with_breaker("jev", ask)
                if judge_model is not None:
                    judge_call = self._with_breaker("judge", judge_model.score, judge_model.name)
            await semantic.decide(
                ctx, policy, classifier_call, judge_call, relaxed=evaluator.relaxed(ctx, "semantic")
            )
            if judge is None:  # an injected judge never starts a shadow check
                shadow.maybe_start(ctx, policy, self.audit, self.shadow)
        except Exception as exc:
            self._fail_open(ctx, exc)
        finally:
            ctx.guard_ms = round(ctx.guard_ms + (time.perf_counter() - started) * 1000, 1)
        return ctx

    def finish(self, ctx: RequestContext) -> Decision:
        """Write the decision row (once per request) and return the decision."""
        row = decision_row(ctx)
        if not ctx.row_written:
            with contextlib.suppress(Exception):
                self.audit.write(row)
            ctx.row_written = True
        ctx.semantic_pending = False
        # The logger joins the usage row with this context by request id.
        self.cache.put(ctx.request_id, ctx)
        message = ctx.message if ctx.decision == "block" else None
        return Decision(ctx.decision, ctx.rule, ctx.would_block, message, row, ctx)

    # ------------------------------------------------------------------ one text, no request

    def check_text(self, text: str, *, source: str = "prompt", team: str | None = None) -> dict:
        """Deterministic checks on one text (normalisation, rules, packs, signatures). Never raises.

        Used by the MCP tool checks on tool arguments and results. Returns ``decision``
        (allow, flag or block), the findings, the normalisation statistics, the data class and
        the policy version.
        """
        result: dict[str, Any] = {
            "decision": "allow",
            "findings": [],
            "normalisation": dict(detectors.NO_NORMALISATION),
            "data_class_detected": "public",
            "policy_version": None,
        }
        try:
            if not isinstance(text, str):
                text = str(text)
            source = source if source in ("prompt", "tool_result", "tool_call") else "prompt"
            policy = self.policy_store.current()
            ctx = RequestContext()
            ctx.profile = policy.profile(self.teams.current().profile_of(team) if team else None)
            ctx.mode = policy.effective_mode(ctx.profile)
            ctx.policy_version = policy.version
            ctx.pieces = [Piece(text, source)]
            self._check_pieces(ctx, policy)
            decision = "block" if ctx.decision == "block" else ("flag" if ctx.flagged else "allow")
            result.update(
                decision=decision,
                findings=[f.as_dict() for f in ctx.findings],
                normalisation=dict(ctx.normalisation),
                data_class_detected=ctx.data_class_detected,
                policy_version=policy.version,
            )
        except Exception as exc:
            result["error"] = f"internal: {type(exc).__name__}"
        return result

    # ------------------------------------------------------------------ deterministic steps

    def _deterministic(self, data: dict, call_type: str | None, ctx: RequestContext) -> Policy:
        """Extract the newest turn, resolve profile and route, detect, decide, plan masking."""
        model = data.get("model")
        ctx.endpoint = detect_endpoint(data, call_type)
        ctx.model_requested = model if isinstance(model, str) else None
        if ctx.model_routed is None:
            ctx.model_routed = ctx.model_requested
        ctx.stream = data.get("stream") is True
        ctx.pieces = newest_pieces(data, claude_code=is_claude_code(data))

        policy = self.policy_store.current()
        ctx.policy_version = policy.version
        ctx.profile = policy.profile(ctx.identity.profile)
        ctx.mode = policy.effective_mode(ctx.profile, ctx.identity.mode)
        ctx.session = loops.session_id(
            session_header(data), data.get("litellm_session_id"), ctx.identity.key_id, self.clock()
        )
        ctx.route = ctx.route_hint or route_of(data)
        self._apply_break_glass(ctx, data, policy)
        self._check_pieces(ctx, policy)
        evaluator.plan_masking(ctx, policy, has_secret=bool(self.masking_secret))
        ctx.semantic_texts = detectors.semantic_texts(ctx.pieces, policy)
        ctx.text_chars = sum(len(t) for t in ctx.semantic_texts.values())
        effects.mask_semantic_copy(ctx, self._masker(ctx, policy))
        if ctx.decision != "block":
            evaluator.apply_governance(ctx, self.teams.current(), self.catalogue.current())
        return policy

    def _check_pieces(self, ctx: RequestContext, policy: Policy) -> None:
        """Detectors over ``ctx.pieces``, then the block or flag decision."""
        found = detectors.detect(
            ctx.pieces, policy, self._feed(), block_hidden=ctx.profile.semantic_action == "block"
        )
        ctx.pieces, ctx.findings, ctx.normalisation = found.pieces, found.findings, found.normalisation
        evaluator.apply_findings(ctx)

    def _feed(self):
        try:
            return self.signatures.current()
        except Exception:
            return None

    def _masker(self, ctx: RequestContext, policy: Policy) -> masking.Masker:
        entities = masking.detector_entities(policy.masking.get("entities") or ())
        return masking.Masker(entities, ctx.session or "none", self.masking_secret)

    def _apply_break_glass(self, ctx: RequestContext, data: dict, policy: Policy) -> None:
        """A valid x-ctrl-ai-break-glass token relaxes the controls it names."""
        try:
            headers = (data.get("proxy_server_request") or {}).get("headers") or {}
            token = headers.get("x-ctrl-ai-break-glass") if isinstance(headers, dict) else None
        except Exception:
            token = None
        if not token or not policy.break_glass.get("enabled", True):
            return
        now = self.clock()
        never_relax = list(policy.break_glass.get("never_relax") or [])
        record, field, event = breakglass.check(
            token,
            self.break_glass_secret,
            self.break_glass_register.current(),
            ctx.identity.team,
            ctx.identity.user,
            never_relax,
            now,
        )
        ctx.break_glass = field
        ctx.never_relax = frozenset(never_relax)
        if record is not None and event == "use" and self.break_glass_uses.use(record["id"], now):
            self._write_row(break_glass_row("use", record))
        elif record is not None and event == "expire" and self.break_glass_uses.expire(record["id"]):
            self._write_row(break_glass_row("expire", record))
        if field and field.get("relaxed"):
            ctx.flagged = True

    async def _check_loop(self, ctx: RequestContext, data: dict, policy: Policy) -> dict | None:
        return await loops.check(
            self.state, ctx.session, latest_prompt_text(data), tool_call_signature(data), policy.loops
        )

    async def _apply_budget(self, ctx: RequestContext, data: dict) -> None:
        """Team budget: reserve the estimate; when exceeded downgrade, block or alert."""
        team = self.teams.current().get(ctx.identity.team)
        if team is None or not team.budget:
            return
        catalogue = self.catalogue.current()
        entry = catalogue.lookup(ctx.model_routed) if catalogue.loaded else None
        price = entry.price if entry is not None else None
        chars = sum(len(p.text) for p in ctx.pieces)
        estimate = budgets.estimate_usd(chars, _max_tokens(data), price)
        record = await budgets.admit(self.state, team.id, team.budget, estimate)
        ctx.reserved_usd = record.pop("reserved", 0.0)
        ctx.budget_month = record.pop("month", None)
        if price is None and record["state"] != "unavailable":
            record["price_known"] = False
        ctx.budget = record
        action = evaluator.budget_action(ctx, record)
        if action is None:
            return
        # Not admitted on the requested model: release its reservation.
        await budgets.release(self.state, team.id, ctx.budget_month or "", ctx.reserved_usd)
        ctx.reserved_usd = 0.0
        target = team.budget.get("downgrade_to")
        if action == "downgrade" and target and target != ctx.model_routed:
            result = govern(
                target,
                team.id,
                None,
                evaluator.governance_data_class(ctx),
                catalogue,
                subscription=ctx.route == "claude_subscription",
            )
            if result.decision == "allow":
                ctx.model_routed = target
                ctx.decision = "reroute"
                ctx.route_reason = "budget"
                return
        evaluator.refuse_over_budget(ctx, team.id, record)

    # ------------------------------------------------------------------ semantic calls

    async def ask_classifier(self, model: DecisionModel | None, texts: dict[str, str]) -> Score:
        """One classifier call per source present, in parallel; the highest score wins.

        Answers are merged (``tool_result:`` prefix for the tool-result questions when both ran),
        costs and tokens are summed, latency is the longest call. Without a classifier the
        answer is ``unavailable`` / ``not_configured``.
        """
        if model is None:
            return Score.unavailable("not_configured")
        sources = list(texts)
        scores = await asyncio.gather(*(self._ask_classifier(model, texts[s], s) for s in sources))
        if len(scores) == 1:
            return scores[0]
        ok = [s for s in scores if s.ok]
        if not ok:
            return scores[0]
        best = max(ok, key=lambda s: s.score or 0.0)
        answers: dict[str, float] = {}
        for source, s in zip(sources, scores, strict=False):
            for qid, value in (s.answers or {}).items():
                answers[qid if source == "prompt" else f"{source}:{qid}"] = value
        return replace(
            best,
            answers=answers,
            cost_usd=sum(s.cost_usd or 0.0 for s in ok),
            input_tokens=sum(s.input_tokens or 0 for s in ok),
            latency_ms=max(s.latency_ms or 0.0 for s in scores),
            truncated=any(s.truncated for s in scores),
        )

    async def _ask_classifier(self, model: DecisionModel, text: str, source: str) -> Score:
        """The model's answer as returned; ``unavailable`` if the call fails or overruns."""
        started = time.perf_counter()
        try:
            limit = self.classifier_timeout_s + CLASSIFIER_TIMEOUT_MARGIN_S
            return await asyncio.wait_for(model.score(text, source), timeout=limit)
        except Exception as exc:
            reason = "timeout" if isinstance(exc, asyncio.TimeoutError) else "exception"
            return Score.unavailable(reason, round((time.perf_counter() - started) * 1000, 1))

    def _with_breaker(
        self, component: str, call: Callable[..., Awaitable[Score]], model_name: str | None = None
    ) -> Callable[..., Awaitable[Score]]:
        """Wrap a classifier (``jev``) or judge (``judge``) call in that component's circuit breaker.

        The component names are the ones in incident rows and on the admin panel. A classifier
        that answers ``skipped`` or ``disabled`` is not failing; a judge that answers anything
        but ``ok`` is.
        """
        outage = self.outage

        async def wrapped(*args: Any) -> Score:
            if not outage.allow(component):
                return Score.unavailable("circuit_open", model=model_name)
            result = await call(*args)
            if result.status == "ok":
                outage.record(component, True)
            elif component == "judge" or result.status in ("unavailable", "error"):
                outage.record(component, False, result.error or result.status)
            return result

        return wrapped

    # ------------------------------------------------------------------ helpers

    def _write_row(self, row: dict) -> None:
        with contextlib.suppress(Exception):
            self.audit.write(row)

    @staticmethod
    def _fail_open(ctx: RequestContext, exc: Exception) -> None:
        ctx.decision = "allow" if ctx.decision != "reroute" else "reroute"
        ctx.error = f"internal: {type(exc).__name__}"
        ctx.message = None


def _max_tokens(data: dict) -> int | None:
    for key in ("max_tokens", "max_output_tokens", "max_completion_tokens"):
        value = data.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None
