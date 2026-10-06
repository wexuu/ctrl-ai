"""Decision models: one interface for "how likely is this text an attack on the agent".

The engine uses a decision model in three roles: the classifier (fast, asked on every
request), the judge (asked when the classifier rejects, is unsure or is down) and the shadow
check (asked again, in the background, about a sample of what the classifier accepted). Each
role is configured with a model spec (``build_model``):

``jev``
    The Jev decision API (``JevModel``).
``none`` or empty
    No model in that role.
anything else
    A LiteLLM model string such as ``groq/openai/gpt-oss-safeguard-20b``,
    ``anthropic/claude-haiku-4-5`` or ``openai/llama3.1`` with an ``api_base`` pointing at a
    local OpenAI-compatible server (``LiteLLMModel``).

Every model returns a ``Score`` and never raises. The audit rows keep their existing shapes;
``Score`` renders them (``jev_row``, ``judge_row``, ``shadow_row``).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from typing import Any, Protocol

from ctrl_ai.core.scores import SampleCounts, Score
from ctrl_ai.core.settings import JevSettings
from ctrl_ai.semantic import judge as prompt
from ctrl_ai.semantic.jev.client import check_text as jev_check_text

Completion = Callable[..., Awaitable[Any]]

DEFAULT_TIMEOUT_S = 8.0
# Sent when a model has an ``api_base`` but no key: local OpenAI-compatible servers (Ollama,
# vLLM, LM Studio) ignore the key but reject a request whose Authorization header is empty.
PLACEHOLDER_API_KEY = "no-key"
# The asyncio backstop sits slightly behind the timeout the call itself enforces.
TIMEOUT_MARGIN_S = 0.5
POSITIVE_FROM = 0.5


class DecisionModel(Protocol):
    """A back end that scores a text. Implementations never raise."""

    name: str

    async def score(self, text: str, source: str) -> Score: ...

    async def sample(self, text: str, source: str, n: int) -> Score: ...


def _ms_since(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 1)


def single_sample(result: Score) -> Score:
    """``sample`` for a deterministic model: one answer stands for all of them."""
    if not result.ok:
        return replace(result, sampling=SampleCounts(1, 0, 0))
    yes = 1 if (result.score or 0.0) >= POSITIVE_FROM else 0
    categories = (result.category,) if yes and result.category else ()
    return replace(result, sampling=SampleCounts(1, 1, yes, categories))


# ---------------------------------------------------------------- Jev


class JevModel:
    """The Jev decision API. Settings are read once, when the model is built."""

    name = "jev"

    def __init__(self, settings: JevSettings, *, transport: Any = None):
        self.settings = settings
        self.timeout_s = settings.timeout_s
        self._transport = transport

    async def score(self, text: str, source: str) -> Score:
        verdict = await jev_check_text(text, source=source, settings=self.settings, transport=self._transport)
        return Score.from_jev(verdict)

    async def sample(self, text: str, source: str, n: int) -> Score:
        return single_sample(await self.score(text, source))


# ---------------------------------------------------------------- LiteLLM


async def _litellm_completion(**kwargs) -> Any:
    import litellm

    return await litellm.acompletion(**kwargs)


class LiteLLMModel:
    """Any model LiteLLM can call, asked with the judge prompt (``semantic/judge.py``).

    The call runs in-process (``litellm.acompletion``), so it does not pass through the proxy's
    guardrails and our logger skips it. ``provider_keys`` maps a spec prefix (``groq``,
    ``anthropic``) to its API key. With an ``api_base`` and no key, a placeholder key is sent
    (``PLACEHOLDER_API_KEY``), which local OpenAI-compatible servers need.
    """

    def __init__(
        self,
        spec: str,
        *,
        api_base: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        provider_keys: Mapping[str, str] | None = None,
        catalogue: Any = None,
        completion: Completion | None = None,
    ):
        self.name = spec
        self.api_base = api_base or None
        self.timeout_s = timeout_s if timeout_s > 0 else DEFAULT_TIMEOUT_S
        self._keys = {k: v for k, v in (provider_keys or {}).items() if v}
        self._catalogue = catalogue
        self._completion = completion or _litellm_completion

    def api_key(self) -> str | None:
        key = self._keys.get(self.name.split("/", 1)[0])
        if key:
            return key
        return PLACEHOLDER_API_KEY if self.api_base else None

    def request(self, text: str, source: str, temperature: float) -> dict:
        """The keyword arguments for one completion call."""
        kwargs: dict[str, Any] = {
            "model": self.name,
            "messages": prompt.messages(text, source),
            "max_tokens": prompt.MAX_TOKENS,
            "temperature": temperature,
            "timeout": self.timeout_s,
            "num_retries": 0,
            "metadata": {"ctrl_ai_internal": True},
        }
        if "gpt-oss" in self.name:
            kwargs["reasoning_effort"] = "low"
        if self.api_base:
            kwargs["api_base"] = self.api_base
        key = self.api_key()
        if key:
            kwargs["api_key"] = key
        return kwargs

    def _current_catalogue(self) -> Any:
        try:
            return self._catalogue.current() if self._catalogue is not None else None
        except Exception:
            return None

    async def score(self, text: str, source: str) -> Score:
        return await self._ask(text, source, 0.0)

    async def _ask(self, text: str, source: str, temperature: float) -> Score:
        started = time.perf_counter()
        try:
            call = self._completion(**self.request(text, source, temperature))
            response = await asyncio.wait_for(call, timeout=self.timeout_s + TIMEOUT_MARGIN_S)
            content, cost = prompt.content_and_cost(response, self.name, self._current_catalogue())
            value = prompt.parse_verdict(content)
            if value is None:
                return Score(
                    "error",
                    model=self.name,
                    latency_ms=_ms_since(started),
                    cost_usd=cost,
                    error="unparseable",
                )
            category, reason = prompt.parse_details(content)
            return Score(
                "ok",
                score=round(value, 4),
                model=self.name,
                latency_ms=_ms_since(started),
                cost_usd=cost,
                category=category,
                reason=reason,
            )
        except TimeoutError:
            return Score.unavailable("timeout", _ms_since(started), self.name)
        except Exception as exc:
            name = type(exc).__name__
            return Score.unavailable(
                "timeout" if "Timeout" in name else f"error: {name}", _ms_since(started), self.name
            )

    async def sample(self, text: str, source: str, n: int) -> Score:
        """Ask ``n`` times at temperature 1, one after another (free-tier rate limits). The score
        is the share of yes verdicts among the answers that parsed."""
        started = time.perf_counter()
        answers = [await self._ask(text, source, 1.0) for _ in range(max(1, n))]
        ok = [a for a in answers if a.ok]
        yes = [a for a in ok if (a.score or 0.0) >= POSITIVE_FROM]
        cost = sum(a.cost_usd or 0 for a in answers)
        categories = tuple(sorted({a.category for a in yes if a.category}))
        return Score(
            "ok" if ok else answers[-1].status,
            score=round(len(yes) / len(ok), 4) if ok else None,
            model=self.name,
            latency_ms=_ms_since(started),
            cost_usd=round(cost, 8) or None,
            sampling=SampleCounts(len(answers), len(ok), len(yes), categories),
        )


# ---------------------------------------------------------------- static


class StaticModel:
    """Always the same answer: for tests, and for set-ups that allow without asking anyone."""

    def __init__(
        self,
        score: float | None = 0.0,
        *,
        status: str = "ok",
        name: str = "static",
        error: str | None = None,
        category: str | None = None,
        reason: str | None = None,
        answers: dict[str, float] | None = None,
    ):
        self.name = name
        self.result = Score(
            status,
            score=score if status == "ok" else None,
            model=name,
            error=error,
            category=category,
            reason=reason,
            answers=answers,
        )
        self.calls: list[tuple[str, str]] = []

    async def score(self, text: str, source: str) -> Score:
        self.calls.append((text, source))
        return self.result

    async def sample(self, text: str, source: str, n: int) -> Score:
        return single_sample(await self.score(text, source))


# ---------------------------------------------------------------- specs


def build_model(
    spec: str | None,
    *,
    jev_settings: JevSettings | None = None,
    api_base: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    provider_keys: Mapping[str, str] | None = None,
    catalogue: Any = None,
) -> DecisionModel | None:
    """The model a spec names: ``jev``, ``none`` (or empty) for no model, else a LiteLLM model."""
    spec = (spec or "").strip()
    if spec.lower() in ("", "none"):
        return None
    if spec.lower() == "jev":
        if jev_settings is None:
            raise ValueError("the jev model needs the JEV_* settings")
        return JevModel(jev_settings)
    return LiteLLMModel(
        spec, api_base=api_base, timeout_s=timeout_s, provider_keys=provider_keys, catalogue=catalogue
    )
