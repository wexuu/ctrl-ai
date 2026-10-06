"""Build the Jev trust report from saved predictions, labels and explanations.

Pure assembly over files the worker wrote: no model calls. Every number carries its
denominator and the dataset mode; undefined values are null with a reason.
"""

from __future__ import annotations

import csv
import json
import math
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from ctrl_ai.evaluation import metrics as M
from ctrl_ai.evaluation.labels import resolve
from ctrl_ai.evaluation.monitor import run_scenarios

SCHEMA_VERSION = "xai-report-1"
CUTOFF = M.DEFAULT_CUTOFF


def _quality(pairs: list[tuple[float, int]]) -> dict:
    if not pairs:
        return {"n": 0, "state": "awaiting_labels"}
    p, y = [a for a, _ in pairs], [b for _, b in pairs]
    pos = sum(y)
    q = {
        "n": len(pairs),
        "positives": pos,
        "negatives": len(y) - pos,
        "log_loss": M.log_loss(p, y),
        "brier": M.brier(p, y),
        "reliability": M.reliability(p, y),
        "confusion": M.confusion(p, y, CUTOFF),
        "diagnostics": {str(c): M.confusion(p, y, c) for c in (0.35, 0.7)},
        "state": "ok",
    }
    warn = []
    if pos < 30 or len(y) - pos < 30:
        warn.append("fewer than 30 positives or negatives: error rates are indicative only")
    q["warnings"] = warn
    tp = int(q["confusion"]["cells"]["tp"])
    q["recall_interval"] = (
        M.wilson(tp, pos) if pos else {"lo": None, "hi": None, "reason": "no_positive_labels"}
    )
    return q


def _by_criterion(rows: list[dict], label_of) -> dict:
    out: dict = {}
    crits = sorted({r["criterion"] for r in rows})
    for crit in crits:
        sel = [r for r in rows if r["criterion"] == crit]
        pairs, excluded = [], {}
        for r in sel:
            lab = label_of(r)
            if lab is None or lab.get("state") != "resolved":
                reason = "no_label" if lab is None else lab["state"]
                excluded[reason] = excluded.get(reason, 0) + 1
                continue
            if r["jev"]["status"] != "ok" or r["jev"]["score"] is None:
                excluded["jev_" + r["jev"]["status"]] = excluded.get("jev_" + r["jev"]["status"], 0) + 1
                continue
            pairs.append((r["jev"]["score"], lab["label"]))
        q = _quality(pairs)
        q.update(selected=len(sel), exclusions=excluded)
        out[crit] = q
    return out


def _agreement(rows: list[dict]) -> dict:
    def block(sel: list[dict]) -> dict:
        a, b, excl = [], [], {}
        for r in sel:
            sg = r["safeguard"]
            if r["jev"]["status"] != "ok":
                excl["jev_" + r["jev"]["status"]] = excl.get("jev_" + r["jev"]["status"], 0) + 1
            elif sg["status"] != "ok":
                key = sg.get("error") or sg["status"]
                excl[key] = excl.get(key, 0) + 1
            else:
                a.append(int(r["jev"]["score"] >= CUTOFF))
                b.append(sg["verdict"])
        res = M.agreement(a, b)
        res.update(
            selected=len(sel),
            valid=len(a),
            coverage=(len(a) / len(sel)) if sel else None,
            exclusions=excl,
            agreement_interval=M.wilson(int(res["cells"]["n00"] + res["cells"]["n11"]), len(a)),
        )
        return res

    return {
        "all": block(rows),
        "by_criterion": {
            c: block([r for r in rows if r["criterion"] == c]) for c in sorted({r["criterion"] for r in rows})
        },
    }


def _numeric(rows: list[dict]) -> dict:
    def block(sel: list[dict]) -> dict:
        p, q, excl = [], [], {}
        for r in sel:
            pg = r["prompt_guard"]
            if pg.get("error") == "criterion_not_covered":
                continue
            if r["jev"]["status"] != "ok":
                excl["jev_" + r["jev"]["status"]] = excl.get("jev_" + r["jev"]["status"], 0) + 1
            elif pg["status"] != "ok":
                key = pg.get("error") or pg["status"]
                excl[key] = excl.get(key, 0) + 1
            else:
                p.append(r["jev"]["score"])
                q.append(pg["score"])
        covered = len(p) + sum(excl.values())
        res = M.numeric_divergence(p, q)
        res.pop("per_case", None)
        res.update(
            selected=covered, valid=len(p), coverage=(len(p) / covered) if covered else None, exclusions=excl
        )
        return res

    crits = sorted(
        {r["criterion"] for r in rows if r["prompt_guard"].get("error") != "criterion_not_covered"}
    )
    return {
        "all": block(rows),
        "by_criterion": {c: block([r for r in rows if r["criterion"] == c]) for c in crits},
        "score_kind": "classifier_probability",
        "note": "Prompt Guard's score is a classifier output, not a calibrated probability. "
        "Jensen-Shannon divergence shows how differently the two models score the same text; "
        "it does not say which one is right.",
    }


def metric_fixture(path: Path) -> dict | None:
    """The four-observation metric fixture, computed live (illustrative, not a measurement)."""
    if not path.is_file():
        return None
    rows = list(csv.DictReader(path.open()))
    p = [float(r["jev_score"]) for r in rows]
    y = [int(r["fixture_label"]) for r in rows]
    q = [float(r["reviewer_score"]) for r in rows]
    a = [int(r["jev_audit_verdict"]) for r in rows]
    b = [int(r["reviewer_audit_verdict"]) for r in rows]
    return {
        "mode": "illustrative_fixture",
        "n": len(rows),
        "log_loss": M.log_loss(p, y)["value"],
        "brier": M.brier(p, y)["value"],
        "ece": M.reliability(p, y)["ece"],
        "confusion": M.confusion(p, y)["cells"],
        "agreement": M.agreement(a, b),
        "numeric": {k: v for k, v in M.numeric_divergence(p, q).items()},
    }


def build(
    *,
    run: dict,
    predictions: list[dict],
    labels: list[dict],
    fixture_expected: list[dict],
    explanations: list[dict],
    cases: list[dict],
    windows_csv: Path | None = None,
    metric_csv: Path | None = None,
    mode: str = "measured_synthetic",
) -> dict:
    human = resolve(labels)
    fixture = {
        (f["case_id"], f["criterion"]): (
            {"state": "resolved", "label": f["label"]}
            if f["label"] is not None
            else {"state": "insufficient_context"}
        )
        for f in fixture_expected
    }
    case_by = {c["case_id"]: c for c in cases}
    human_q = _by_criterion(predictions, lambda r: human.get((r["case_id"], r["criterion"])))
    fixture_q = _by_criterion(predictions, lambda r: fixture.get((r["case_id"], r["criterion"])))
    human_labeled = sum(1 for v in human.values() if v["state"] == "resolved")
    example = resolve(labels, origin="synthetic_example")
    example_q = _by_criterion(predictions, lambda r: example.get((r["case_id"], r["criterion"])))
    example_labeled = sum(1 for v in example.values() if v["state"] == "resolved")
    table = []
    for r in predictions:
        key = (r["case_id"], r["criterion"])
        c = case_by.get(r["case_id"], {})
        table.append(
            {
                "case_id": r["case_id"],
                "family_id": c.get("family_id"),
                "source": c.get("source"),
                "criterion": r["criterion"],
                "input_chars": r.get("input_chars"),
                "jev_status": r["jev"]["status"],
                "jev_score": r["jev"]["score"],
                "jev_truncated": r["jev"].get("truncated"),
                "safeguard_status": r["safeguard"]["status"],
                "safeguard_verdict": r["safeguard"]["verdict"],
                "safeguard_error": r["safeguard"].get("error"),
                "prompt_guard_status": r["prompt_guard"]["status"],
                "prompt_guard_score": r["prompt_guard"]["score"],
                "prompt_guard_error": r["prompt_guard"].get("error"),
                "human": (human.get(key) or {"state": "awaiting_labels"}),
                "example": (example.get(key) or {"state": "awaiting_labels"}),
                "fixture_label": (fixture.get(key) or {}).get("label"),
            }
        )
    ex_targets = len(explanations)
    ex_supported = sum(1 for e in explanations if e.get("supported"))
    report = {
        "schema_version": SCHEMA_VERSION,
        "report_id": f"xai-{run['run_id']}",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "mode": mode,
        "run": run,
        "dataset": {
            "id": "xai",
            "version": "v1",
            "cases": len(cases),
            "families": len({c["family_id"] for c in cases}),
            "request_criterion_pairs": len(predictions),
            "input_origin": "authored_synthetic",
        },
        "cutoff": CUTOFF,
        "quality": {
            "human": {
                "label_origin": "independent_human",
                "labeled_pairs": human_labeled,
                "state": "ok" if human_labeled else "awaiting_labels",
                "by_criterion": human_q,
            },
            "example": {
                "label_origin": "synthetic_example",
                "labeled_pairs": example_labeled,
                "reviewers": sorted({r for v in example.values() for r in v.get("reviewers", [])}),
                "state": "ok" if example_labeled else "awaiting_labels",
                "by_criterion": example_q,
                "note": "Generated example labels that show how reviewer labels flow into these metrics. "
                "Not made by people; never counted as independent human labels.",
            },
            "fixture": {
                "label_origin": "fixture_expected",
                "by_criterion": fixture_q,
                "note": "Answer key written by the casebook authors. It tests the pipeline and is not "
                "an independent human judgement.",
            },
        },
        "agreement": _agreement(predictions),
        "numeric": _numeric(predictions),
        "explanations": {
            "targets": ex_targets,
            "supported": ex_supported,
            "coverage": (ex_supported / ex_targets) if ex_targets else None,
            "by_status": _count(e.get("status") for e in explanations),
            "items": explanations,
        },
        "cases": table,
        "monitor": run_scenarios(list(csv.DictReader(windows_csv.open())))
        if windows_csv and windows_csv.is_file()
        else [],
        "metric_fixture": metric_fixture(metric_csv) if metric_csv else None,
    }
    _check_finite(report)
    return report


def _count(values) -> dict:
    out: dict = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


def _check_finite(obj, path="$") -> None:
    if isinstance(obj, float) and not math.isfinite(obj):
        raise ValueError(f"non-finite number at {path}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _check_finite(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _check_finite(v, f"{path}[{i}]")


def publish(report: dict, out_dir: Path) -> Path:
    """Write an immutable version and atomically replace latest.json."""
    out_dir.mkdir(parents=True, exist_ok=True)
    data = json.dumps(report, allow_nan=False, indent=1, ensure_ascii=False)
    version = out_dir / f"{report['report_id']}.json"
    for target in (version, out_dir / "latest.json"):
        fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".tmp-")
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp, target)
    return version
