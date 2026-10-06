"""A decision model's answer about one text, and how a sampled answer came about.

The semantic check, the request context and the audit rows share these; the models that
produce them live in ``semantic/models.py``. ``Score`` renders the existing audit shapes
(``jev_row``, ``judge_row``, ``shadow_row``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SampleCounts:
    """How a sampled score came about: answers asked for, parsed, positive, and their categories."""

    samples: int
    answered: int
    yes: int
    categories: tuple[str, ...] = ()


@dataclass(frozen=True)
class Score:
    """One model's answer about one text. ``score`` is 0..1, the likelihood of an attack."""

    status: str  # ok | unavailable | error | skipped (Jev also reports disabled: no key)
    score: float | None = None
    model: str | None = None
    latency_ms: float = 0.0
    cost_usd: float | None = None
    error: str | None = None
    answers: dict[str, float] | None = None  # per-question scores, where the back end has them
    input_tokens: int | None = None
    truncated: bool = False
    category: str | None = None
    reason: str | None = None  # the model's own words; never written to the audit log
    sampling: SampleCounts | None = None  # set by ``sample``

    @property
    def ok(self) -> bool:
        return self.status == "ok" and isinstance(self.score, (int, float))

    @classmethod
    def unavailable(cls, error: str, latency_ms: float = 0.0, model: str | None = None) -> Score:
        return cls("unavailable", model=model, latency_ms=latency_ms, error=error)

    @classmethod
    def skipped(cls) -> Score:
        return cls("skipped")

    @classmethod
    def from_jev(cls, verdict: Mapping[str, Any]) -> Score:
        """A Jev client verdict (the nine-key dictionary) as a Score."""
        attack = verdict.get("attack")
        answers = verdict.get("answers")
        return cls(
            status=str(verdict.get("status") or "error"),
            score=float(attack)
            if isinstance(attack, (int, float)) and not isinstance(attack, bool)
            else None,
            model=verdict.get("model"),
            latency_ms=float(verdict.get("latency_ms") or 0.0),
            cost_usd=verdict.get("cost_usd"),
            error=verdict.get("error"),
            answers=dict(answers) if isinstance(answers, dict) else None,
            input_tokens=verdict.get("input_tokens"),
            truncated=bool(verdict.get("truncated")),
        )

    def jev_row(self) -> dict:
        """The decision row's ``jev`` field: the nine keys of the Jev verdict contract."""
        return {
            "status": self.status,
            "attack": self.score,
            "answers": dict(self.answers) if self.answers is not None else None,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "cost_usd": self.cost_usd,
            "latency_ms": self.latency_ms,
            "truncated": self.truncated,
            "error": self.error,
        }

    def judge_row(self) -> dict:
        """The decision row's ``judge`` field. The free-text reason may paraphrase the prompt,
        so only the category is logged."""
        return {
            "status": self.status,
            "score": self.score,
            "model": self.model,
            "latency_ms": self.latency_ms,
            "cost_usd": self.cost_usd,
            "error": self.error,
            "category": self.category,
        }

    def shadow_row(self) -> dict:
        """The shadow row's ``second`` field: the sampled probability and how it came about."""
        if self.sampling is None:
            return {"status": self.status, "p": self.score, "error": self.error}
        return {
            "status": self.status,
            "p": self.score,
            "samples": self.sampling.samples,
            "answered": self.sampling.answered,
            "yes": self.sampling.yes,
            "categories": list(self.sampling.categories),
            "model": self.model,
            "latency_ms": self.latency_ms,
            "cost_usd": self.cost_usd,
        }
