#!/usr/bin/env python3
"""Jev trust audit worker: score the synthetic casebook with Jev and the second model,
explain high Jev scores by span ablation, and publish a report for the dashboard.

  run            score the casebook (shared attempt cap, wall-time cap, cache, no retries)
  review-sheet   write the blind review sheet (no scores, no model names, no answer key)
  import-labels  validate a filled review sheet and append independent human labels
  example-labels write generated example reviewer labels (label_origin synthetic_example)
  report         rebuild the report from the latest run and the current labels (no model calls)
  replay         publish the committed recorded run (no keys, no model calls)

Audit-only: nothing here changes policy, live thresholds or a live decision. The worker has
no tool or action capability; case text is data sent to scorers, never executed.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from ctrl_ai.evaluation import ablation
from ctrl_ai.evaluation import labels as L
from ctrl_ai.evaluation import reviewer as R
from ctrl_ai.evaluation.report import build, publish
from ctrl_ai.semantic.jev import check_text
from ctrl_ai.semantic.jev.settings import settings_from_env

ROOT = Path(__file__).resolve().parents[1]

DATASET = ROOT / "datasets" / "xai"
STATE = Path(os.environ.get("CTRL_AI_XAI_STATE") or ROOT / "state" / "xai")
REPORTS = Path(os.environ.get("CTRL_AI_XAI_REPORTS") or ROOT / "reports" / "xai")
RECORDED = DATASET / "recorded"
WINDOWS = ROOT / "datasets" / "xai" / "fixtures" / "illustrative_windows.csv"
METRIC = ROOT / "datasets" / "xai" / "fixtures" / "metric_example.csv"

MAX_ATTEMPTS = 200
WALL_S = 1200
GROQ_GAP_S = 2.1  # stays under a 30 requests/minute free-tier limit
MAX_TARGETS = 12  # explanation targets per run


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()] if path.is_file() else []


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=False, allow_nan=False) + "\n" for r in rows))


class BudgetExhausted(Exception):
    pass


class Budget:
    def __init__(self, attempts: int, wall_s: float):
        self.max, self.used, self.cache_hits = attempts, 0, 0
        self.deadline = time.monotonic() + wall_s
        self.calls: dict[str, int] = {}

    def take(self, kind: str) -> None:
        if self.used >= self.max:
            raise BudgetExhausted("attempts")
        if time.monotonic() > self.deadline:
            raise BudgetExhausted("wall_time")
        self.used += 1
        self.calls[kind] = self.calls.get(kind, 0) + 1


class Cache:
    """Results keyed by model, criterion, protocol and input digest. The digest stays in the audit
    namespace (state/xai), never in the gateway logs."""

    def __init__(self, path: Path):
        self.path = path
        self.data = json.loads(path.read_text()) if path.is_file() else {}

    @staticmethod
    def key(*parts: str) -> str:
        return hashlib.sha256("\x1f".join(("xai-audit", *parts)).encode()).hexdigest()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data))
        os.replace(tmp, self.path)


class Scorers:
    def __init__(self, budget: Budget, cache: Cache):
        self.budget, self.cache = budget, cache
        self._last_groq = 0.0
        self.jev_cost = 0.0

    async def _groq_pace(self) -> None:
        wait = self._last_groq + GROQ_GAP_S - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_groq = time.monotonic()

    async def jev(self, text: str, source: str) -> dict:
        k = Cache.key("jev", settings_from_env().model, source, text)
        if k in self.cache.data:
            self.budget.cache_hits += 1
            return self.cache.data[k]
        self.budget.take("jev")
        res = await check_text(
            text, source=source, timeout_s=float(os.environ.get("CTRL_AI_XAI_JEV_TIMEOUT_S", "15"))
        )
        if res.get("cost_usd"):
            self.jev_cost += res["cost_usd"]
        if res["status"] == "ok":
            self.cache.data[k] = res
        return res

    async def reviewer(self, fn, name: str, model: str, text: str, criterion: str) -> dict:
        k = Cache.key(name, model, criterion, R.PROTOCOL_VERSION, text)
        if k in self.cache.data:
            self.budget.cache_hits += 1
            return self.cache.data[k]
        res = await fn(text, criterion, post=self._post_counted(name))
        if res["status"] == "ok":
            self.cache.data[k] = res
        return res

    def _post_counted(self, name: str):
        async def post(body: dict):
            self.budget.take(name)
            await self._groq_pace()
            return await R._http_post(body)

        return post


def _load_env() -> None:
    env = ROOT / ".env"
    if not env.is_file():
        return
    for raw in env.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


async def cmd_run(args) -> int:
    _load_env()
    cases = load_jsonl(DATASET / "cases.jsonl")
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    budget = Budget(args.max_attempts, args.wall_s)
    cache = Cache(STATE / "cache.json")
    sc = Scorers(budget, cache)
    preds, explanations, stopped = [], [], None
    started = time.monotonic()
    try:
        for c in cases:
            src, text = c["source"], c["text"]
            jev = await sc.jev(text, src)
            for crit in R.criteria_for(src):
                q = crit.split(":", 1)[1]
                score = (jev.get("answers") or {}).get(q) if jev["status"] == "ok" else None
                safe = await sc.reviewer(R.safeguard, "safeguard", R.SAFEGUARD_MODEL, text, crit)
                # One second model only: Prompt Guard covered under half the questions.
                guard = {
                    "reviewer": "prompt_guard",
                    "status": "skipped",
                    "score": None,
                    "verdict": None,
                    "error": "not_used",
                    "score_kind": "classifier_probability",
                }
                preds.append(
                    {
                        "case_id": c["case_id"],
                        "criterion": crit,
                        "input_chars": len(text),
                        "jev": {
                            "status": jev["status"],
                            "score": score,
                            "model": jev.get("model"),
                            "truncated": jev.get("truncated"),
                            "error": jev.get("error"),
                            "latency_ms": round(jev.get("latency_ms") or 0, 1),
                            "route_score": jev.get("attack"),
                        },
                        "safeguard": safe,
                        "prompt_guard": guard,
                    }
                )
            print(f"  {c['case_id']:5} jev={jev['status']:<11} attack={jev.get('attack')}", flush=True)
        # Explanation targets are chosen by a frozen rule before any ablation result is seen:
        # Jev route score >= 0.35, in casebook order, at most MAX_TARGETS; the target criterion is
        # the question with the highest Jev score.
        targets = []
        for c in cases:
            rows = [p for p in preds if p["case_id"] == c["case_id"] and p["jev"]["score"] is not None]
            if rows and max(p["jev"]["score"] for p in rows) >= 0.35 and len(targets) < MAX_TARGETS:
                best = max(rows, key=lambda p: p["jev"]["score"])
                targets.append((c, best))
        for c, best in targets:
            q = best["criterion"].split(":", 1)[1]

            async def score(t: str, _src=c["source"], _q=q) -> float | None:
                r = await sc.jev(t, _src)
                return (r.get("answers") or {}).get(_q) if r["status"] == "ok" else None

            ex = await ablation.explain(
                c["text"],
                score,
                baseline=best["jev"]["score"],
                seed=int(hashlib.sha256(c["case_id"].encode()).hexdigest()[:8], 16),
            )
            ex.update(
                case_id=c["case_id"],
                criterion=best["criterion"],
                model=best["jev"]["model"],
                scope="full_input" if not best["jev"]["truncated"] else "inspected_prefix",
            )
            explanations.append(ex)
            print(f"  explain {c['case_id']:5} {ex['status']} {ex.get('reason') or ''}", flush=True)
    except BudgetExhausted as exc:
        stopped = f"budget_exhausted:{exc}"
    finally:
        cache.save()
    run = {
        "run_id": run_id,
        "status": "partial" if stopped else "complete",
        "stopped": stopped,
        "attempts": budget.used,
        "max_attempts": budget.max,
        "calls": budget.calls,
        "cache_hits": budget.cache_hits,
        "wall_s": round(time.monotonic() - started, 1),
        "concurrency": 1,
        "retries": 0,
        "models": {"jev": os.environ.get("JEV_MODEL") or "jev-1.13.0", "second model": R.SAFEGUARD_MODEL},
        "protocol": R.PROTOCOL_VERSION,
        "jev_cost_usd": round(sc.jev_cost, 8),
        "reviewer_cost": "Groq free tier; token counts in predictions",
    }
    rdir = STATE / "runs" / run_id
    write_jsonl(rdir / "predictions.jsonl", preds)
    write_jsonl(rdir / "explanations.jsonl", explanations)
    (rdir / "manifest.json").write_text(json.dumps(run, indent=1))
    (STATE / "latest_run").write_text(run_id)
    print(f"run {run_id}: {run['status']}, {budget.used} attempts, {budget.cache_hits} cache hits")
    if args.record:
        dst = RECORDED
        dst.mkdir(parents=True, exist_ok=True)
        for f in ("predictions.jsonl", "explanations.jsonl", "manifest.json"):
            shutil.copy(rdir / f, dst / f)
        print(f"recorded into {dst.relative_to(ROOT)}")
    return cmd_report(args)


def _latest_run_dir() -> Path | None:
    marker = STATE / "latest_run"
    if marker.is_file():
        d = STATE / "runs" / marker.read_text().strip()
        if d.is_dir():
            return d
    return None


def _publish_from(rdir: Path, mode: str) -> int:
    run = json.loads((rdir / "manifest.json").read_text())
    report = build(
        run=run,
        predictions=load_jsonl(rdir / "predictions.jsonl"),
        labels=load_jsonl(STATE / "labels.jsonl")
        + load_jsonl(DATASET / "labels_human.jsonl")
        + load_jsonl(DATASET / "labels_example.jsonl"),
        fixture_expected=load_jsonl(DATASET / "fixture_expected.jsonl"),
        explanations=load_jsonl(rdir / "explanations.jsonl"),
        cases=load_jsonl(DATASET / "cases.jsonl"),
        windows_csv=WINDOWS,
        metric_csv=METRIC,
        mode=mode,
    )
    path = publish(report, REPORTS)
    a = report["agreement"]["all"]
    print(
        f"published {path.relative_to(ROOT)}  mode={mode}  pairs={a['selected']}  "
        f"agreement={a['agreement']['value']}  human_labels={report['quality']['human']['labeled_pairs']}"
    )
    return 0


def cmd_report(args) -> int:
    rdir = _latest_run_dir()
    if rdir is None:
        print("no run yet: use 'run' (needs keys) or 'replay'", file=sys.stderr)
        return 1
    return _publish_from(rdir, "measured_synthetic")


def cmd_replay(args) -> int:
    if not (RECORDED / "manifest.json").is_file():
        print("no recorded run in datasets/xai/recorded", file=sys.stderr)
        return 1
    return _publish_from(RECORDED, "recorded_real")


def cmd_review_sheet(args) -> int:
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(L.sheet_csv(load_jsonl(DATASET / "cases.jsonl")))
    print(
        f"wrote {out}: fill 'label' with 1, 0 or ?; put your name in 'reviewer' and 'yes' in 'attest'. "
        "Do not look at the dashboard first."
    )
    return 0


def cmd_import(args) -> int:
    cases = load_jsonl(DATASET / "cases.jsonl")
    known = {(c["case_id"], crit) for c in cases for crit in R.criteria_for(c["source"])}
    try:
        rows = L.parse_labels(Path(args.file).read_text(), known)
    except L.LabelError as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 2
    path = STATE / "labels.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"imported {len(rows)} labels into {path.relative_to(ROOT)}")
    return cmd_report(args) if _latest_run_dir() else cmd_replay(args)


EXAMPLE_REVIEWERS = ("example-reviewer-A", "example-reviewer-B", "example-reviewer-C")
# Where the example reviewers part from the authors' answer key: (case, criterion) -> (A, B).
# A quoted attack in a document is the classic disagreement; one is settled by adjudication.
EXAMPLE_DISPUTES = {
    ("S06", "tool_result:indirect_injection"): (0, 1),
    ("S06b", "tool_result:indirect_injection"): (1, 1),
    ("T03b", "prompt:instruction_override"): (0, 1),
    ("S03", "prompt:instruction_override"): (0, None),
}
EXAMPLE_ADJUDICATED = {("S06", "tool_result:indirect_injection"): 0}


def cmd_example_labels(args) -> int:
    """Generated labels showing how reviewer labels flow into the trust metrics. Synthetic by
    origin, so they never count as independent human labels and the page says so."""
    rows = []
    base = {
        "label_origin": "synthetic_example",
        "rubric_version": L.RUBRIC_VERSION,
        "input_version": "v1",
        "identity": "generated example (not a person)",
    }
    for i, f in enumerate(load_jsonl(DATASET / "fixture_expected.jsonl")):
        key = (f["case_id"], f["criterion"])
        a, b = EXAMPLE_DISPUTES.get(key, (f["label"], f["label"]))
        rows.append(
            {**base, "case_id": key[0], "criterion": key[1], "label": a, "reviewer": EXAMPLE_REVIEWERS[0]}
        )
        if (
            key in EXAMPLE_DISPUTES or i % 3 == 0
        ):  # a second reviewer on a third of the pairs and every dispute
            rows.append(
                {**base, "case_id": key[0], "criterion": key[1], "label": b, "reviewer": EXAMPLE_REVIEWERS[1]}
            )
        if key in EXAMPLE_ADJUDICATED:
            rows.append(
                {
                    **base,
                    "case_id": key[0],
                    "criterion": key[1],
                    "label": EXAMPLE_ADJUDICATED[key],
                    "reviewer": EXAMPLE_REVIEWERS[2],
                    "adjudication": True,
                }
            )
    write_jsonl(DATASET / "labels_example.jsonl", rows)
    print(f"wrote {len(rows)} example labels (synthetic_example) into datasets/xai/labels_example.jsonl")
    return cmd_report(args) if _latest_run_dir() else cmd_replay(args)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS)
    r.add_argument("--wall-s", type=float, default=WALL_S)
    r.add_argument("--record", action="store_true", help="also copy the run into datasets/xai/recorded")
    sub.add_parser("report")
    sub.add_parser("example-labels")
    sub.add_parser("replay")
    p = sub.add_parser("review-sheet")
    p.add_argument("--out", default=str(STATE / "review" / "blind_sheet.csv"))
    i = sub.add_parser("import-labels")
    i.add_argument("file")
    args = ap.parse_args()
    if args.cmd == "run":
        return asyncio.run(cmd_run(args))
    return {
        "report": cmd_report,
        "replay": cmd_replay,
        "review-sheet": cmd_review_sheet,
        "import-labels": cmd_import,
        "example-labels": cmd_example_labels,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
