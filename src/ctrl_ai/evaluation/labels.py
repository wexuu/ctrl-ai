"""Blind review sheets and independent human labels.

A sheet carries the checked text, its source, the user's task and the criterion definition.
It never carries scores, model names, verdicts or the fixture answer key. Imported labels are
``independent_human`` only when a named reviewer attests to them; the fixture answer key stays
``fixture_expected`` and never enters the human headline. Conflicting reviewers produce a
pending adjudication; insufficient context is a coverage outcome, not a negative.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from ctrl_ai.evaluation.reviewer import CRITERIA, criteria_for

PACKET_FIELDS = [
    "case_id",
    "criterion",
    "source",
    "user_task",
    "criterion_positive",
    "criterion_negative",
    "text",
    "label",
    "reviewer",
    "attest",
]
LABEL_VALUES = {
    "1": 1,
    "positive": 1,
    "yes": 1,
    "0": 0,
    "negative": 0,
    "no": 0,
    "?": None,
    "insufficient": None,
    "insufficient_context": None,
}
RUBRIC_VERSION = "r1"
FORBIDDEN_IN_PACKET = ("score", "jev", "verdict", "model", "expected", "safeguard", "guard")


def sheet_rows(cases: list[dict]) -> list[dict]:
    rows = []
    for c in cases:
        for crit in criteria_for(c["source"]):
            rows.append(
                {
                    "case_id": c["case_id"],
                    "criterion": crit,
                    "source": c["source"],
                    "user_task": c.get("task") or "",
                    "criterion_positive": CRITERIA[crit]["positive"],
                    "criterion_negative": CRITERIA[crit]["negative"],
                    "text": c["text"],
                    "label": "",
                    "reviewer": "",
                    "attest": "",
                }
            )
    return rows


def sheet_csv(cases: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=PACKET_FIELDS)
    w.writeheader()
    w.writerows(sheet_rows(cases))
    return buf.getvalue()


class LabelError(ValueError):
    pass


def parse_labels(text: str, known: set[tuple[str, str]], *, input_version: str = "v1") -> list[dict]:
    """Validate a filled sheet. Rows with an empty label are skipped (not reviewed yet)."""
    out, errors = [], []
    reader = csv.DictReader(io.StringIO(text))
    for n, row in enumerate(reader, start=2):
        raw = (row.get("label") or "").strip().lower()
        if not raw:
            continue
        key = (row.get("case_id", ""), row.get("criterion", ""))
        if key not in known:
            errors.append(f"line {n}: unknown case or criterion")
            continue
        if raw not in LABEL_VALUES:
            errors.append(f"line {n}: label must be 1, 0 or ? (insufficient context)")
            continue
        reviewer = (row.get("reviewer") or "").strip()
        if not reviewer:
            errors.append(f"line {n}: reviewer name is required")
            continue
        if (row.get("attest") or "").strip().lower() not in ("yes", "y", "true", "1"):
            errors.append(f"line {n}: attest must be 'yes' (reviewed blind, without model scores)")
            continue
        out.append(
            {
                "case_id": key[0],
                "criterion": key[1],
                "label": LABEL_VALUES[raw],
                "outcome": "insufficient_context" if LABEL_VALUES[raw] is None else "resolved",
                "reviewer": reviewer,
                "label_origin": "independent_human",
                "rubric_version": RUBRIC_VERSION,
                "input_version": input_version,
                "identity": "attestational (no SSO)",
                "reviewed_at": datetime.now(UTC).isoformat(timespec="seconds"),
            }
        )
    if errors:
        raise LabelError("; ".join(errors[:10]))
    return out


def resolve(labels: list[dict], origin: str = "independent_human") -> dict[tuple[str, str], dict]:
    """One state per (case, criterion): resolved label, insufficient context, or pending adjudication.

    Only labels of ``origin`` count (``independent_human`` by default; ``synthetic_example`` for
    the generated example labels, which never enter the human headline). A reviewer's later label replaces their earlier one;
    an adjudication row (``adjudication: true``) settles a conflict without erasing it.
    """
    per: dict[tuple[str, str], dict[str, dict]] = {}
    adjudicated: dict[tuple[str, str], dict] = {}
    for lab in labels:
        if lab.get("label_origin") != origin:
            continue
        key = (lab["case_id"], lab["criterion"])
        if lab.get("adjudication"):
            adjudicated[key] = lab
        else:
            per.setdefault(key, {})[lab["reviewer"]] = lab
    out = {}
    for key, by in per.items():
        values = {lab["label"] for lab in by.values()}
        reviewers = sorted(by)
        if key in adjudicated:
            out[key] = {
                "state": "resolved",
                "label": adjudicated[key]["label"],
                "reviewers": reviewers,
                "adjudicated": True,
            }
        elif len(values) > 1:
            out[key] = {"state": "pending_adjudication", "label": None, "reviewers": reviewers}
        elif None in values:
            out[key] = {"state": "insufficient_context", "label": None, "reviewers": reviewers}
        else:
            out[key] = {"state": "resolved", "label": values.pop(), "reviewers": reviewers}
    return out
