"""Time the gateway's request path without a network: the deterministic pre-call half and the
whole decision (pre-call, a static classifier and judge, the audit row).

The engine is built from the frozen test configuration in tests/fixtures/config, like the policy
regression harness: no Redis (shared counters fail open), no LiteLLM, no model calls.

    .venv/bin/python scripts/bench_precall.py                 # table
    .venv/bin/python scripts/bench_precall.py --json          # the same as JSON
    .venv/bin/python scripts/bench_precall.py --iterations 1000
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import statistics
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Callable
from pathlib import Path

from ctrl_ai.core.audit import AuditLog
from ctrl_ai.core.context import Identity
from ctrl_ai.core.filestore import FileStore
from ctrl_ai.core.policy import PolicyStore
from ctrl_ai.detect.signatures import EMPTY_FEED, parse_feed
from ctrl_ai.governance.catalogue import EMPTY_CATALOGUE, parse_models
from ctrl_ai.governance.identity import EMPTY_TEAMS, parse_teams
from ctrl_ai.pipeline.engine import Engine
from ctrl_ai.semantic.models import StaticModel

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures" / "config"
TRACED_ITERATIONS = 20
IDENTITY = Identity(
    team="retail-dev",
    department="retail",
    user="bench",
    key_id="k_bench001",
    profile="strict",
    mode="enforce",
)

FILLER = (
    "The quarterly report covers revenue, costs and the outlook for the next two quarters. "
    "Each section lists the figures, the assumptions behind them and the open questions. "
)
LONG_TEXT = (FILLER * 120)[:20_000]
TOOL_OUTPUT = "\n".join(f"{i:05d}  src/module_{i % 40}.py  ok  {FILLER[:60]}" for i in range(260))[:20_000]
REMINDER = (
    "<system-reminder>The user opened src/app.py. Project conventions: keep functions short, "
    "write tests first, never commit secrets.</system-reminder>"
)


def _messages(*messages: dict, **extra) -> dict:
    return {"model": "claude-sonnet-5-5", "max_tokens": 512, "messages": list(messages), **extra}


SHAPES: dict[str, tuple[str, dict]] = {
    "short prompt": (
        "one user message of about 60 characters",
        _messages({"role": "user", "content": "Summarise the attached meeting notes in three bullets."}),
    ),
    "long prompt": (
        "one user message of 20,000 characters of ordinary prose",
        _messages({"role": "user", "content": LONG_TEXT}),
    ),
    "tool result": (
        "a tool call and its 20,000-character output (a file listing) as the newest turn",
        _messages(
            {"role": "user", "content": "Which files changed?"},
            {
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "t1", "name": "run", "input": {"cmd": "git status"}}],
            },
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "t1", "content": TOOL_OUTPUT}],
            },
        ),
    ),
    "masked identifiers": (
        "a prompt with an IBAN, a PESEL, an e-mail address and a phone number, rewritten on the external route",
        _messages(
            {
                "role": "user",
                "content": "Refund PL61 1090 1014 0000 0712 1981 2874 for PESEL 44051401359, "
                "then mail jane.doe@example.com or call +48 601 234 567.",
            }
        ),
    ),
    "claude code": (
        "a Claude Code request: a <system-reminder> block before the prompt, Claude Code's headers",
        _messages(
            {
                "role": "user",
                "content": [{"type": "text", "text": REMINDER + "\nAdd a unit test for parse()."}],
            },
            proxy_server_request={"headers": {"user-agent": "claude-cli/2.1.0 (external, cli)"}},
        ),
    ),
}


def build_engine(audit_path: str) -> Engine:
    return Engine(
        policy_store=PolicyStore(str(FIXTURES / "policy.yaml")),
        audit=AuditLog(audit_path),
        teams=FileStore(str(FIXTURES / "teams.yaml"), parse_teams, EMPTY_TEAMS),
        catalogue=FileStore(str(FIXTURES / "models.yaml"), parse_models, EMPTY_CATALOGUE),
        signatures=FileStore(str(FIXTURES / "signatures.yaml"), parse_feed, EMPTY_FEED),
        classifier=StaticModel(0.02, name="jev-bench"),
        judge=StaticModel(0.05, name="judge-bench"),
        masking_secret="ctrl-ai-bench-masking-secret",
    )


def _fresh(body: dict, n: int) -> dict:
    """A copy of the request whose newest text ends differently each time, so no cache keyed on
    the text can answer for a previous call (pre_call also rewrites the copy when it masks)."""
    data = copy.deepcopy(body)
    last = data["messages"][-1]
    if isinstance(last["content"], str):
        last["content"] += f" #{n}"
    else:
        block = last["content"][-1]
        key = "text" if "text" in block else "content"
        block[key] += f" #{n}"
    return data


async def _time(call: Callable, body: dict, iterations: int) -> list[float]:
    times = []
    for n in range(iterations):
        data = _fresh(body, n)
        started = time.perf_counter()
        await call(data)
        times.append((time.perf_counter() - started) * 1000)
    return times


async def _peak_kib(call: Callable, body: dict) -> float:
    """Largest memory a single call holds at once, from tracemalloc (KiB)."""
    peaks = []
    tracemalloc.start()
    try:
        for n in range(TRACED_ITERATIONS):
            data = _fresh(body, -n - 1)
            tracemalloc.reset_peak()
            before = tracemalloc.get_traced_memory()[0]
            await call(data)
            peaks.append(tracemalloc.get_traced_memory()[1] - before)
    finally:
        tracemalloc.stop()
    return round(statistics.median(peaks) / 1024, 1)


def _summary(times: list[float]) -> dict:
    ordered = sorted(times)
    return {
        "p50_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[max(0, int(len(ordered) * 0.95) - 1)], 3),
        "max_ms": round(ordered[-1], 3),
    }


async def run(iterations: int, warmup: int) -> list[dict]:
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        engine = build_engine(str(Path(tmp) / "audit.jsonl"))

        async def pre_call(data: dict):
            return await engine.pre_call(data, call_type="anthropic_messages", identity=IDENTITY)

        async def evaluate(data: dict):
            return await engine.evaluate(data, call_type="anthropic_messages", identity=IDENTITY)

        for shape, (_description, body) in SHAPES.items():
            for stage, call in (("pre_call", pre_call), ("evaluate", evaluate)):
                await _time(call, body, warmup)
                times = await _time(call, body, iterations)
                results.append(
                    {
                        "shape": shape,
                        "stage": stage,
                        **_summary(times),
                        "peak_kib": await _peak_kib(call, body),
                    }
                )
    return results


def table(results: list[dict]) -> str:
    lines = [
        "| Shape | Stage | p50 ms | p95 ms | max ms | peak KiB |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for r in results:
        lines.append(
            f"| {r['shape']} | {r['stage']} | {r['p50_ms']:.3f} | {r['p95_ms']:.3f} | "
            f"{r['max_ms']:.3f} | {r['peak_kib']:.1f} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Time the gateway's pre-call path and full decision.")
    parser.add_argument("--iterations", type=int, default=300, help="timed calls per shape and stage")
    parser.add_argument("--warmup", type=int, default=30, help="untimed calls first")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = parser.parse_args(argv)
    results = asyncio.run(run(max(1, args.iterations), max(0, args.warmup)))
    if args.json:
        print(json.dumps({"iterations": args.iterations, "results": results}, indent=2))
    else:
        print(table(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
