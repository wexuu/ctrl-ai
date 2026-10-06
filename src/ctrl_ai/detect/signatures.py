"""The known-exploit signature feed (``config/signatures.yaml``), reloaded live."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ctrl_ai.core.filestore import load_yaml
from ctrl_ai.core.schema import validate

DEFAULT_APPLIES_TO = ("prompt", "tool_result")
SEVERITY_BY_CATEGORY = {
    "code_execution": "critical",
    "unsafe_deserialization": "critical",
    "supply_chain": "high",
    "credential_exfiltration": "high",
    "prompt_injection": "medium",
}


@dataclass(frozen=True)
class Signature:
    id: str
    category: str
    source: str
    applies_to: tuple[str, ...]
    pattern: re.Pattern[str] = field(compare=False, repr=False)
    action: str
    severity: str
    guidance: str = ""
    tests: dict = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class Feed:
    feed_version: str
    signatures: tuple[Signature, ...]


EMPTY_FEED = Feed(feed_version="none", signatures=())


def parse_feed(raw: bytes) -> Feed:
    doc = load_yaml(raw)
    validate(doc, "signatures")
    sigs = []
    for entry in doc.get("signatures") or []:
        sigs.append(
            Signature(
                id=entry["id"],
                category=entry["category"],
                source=entry["source"],
                applies_to=tuple(entry.get("applies_to") or DEFAULT_APPLIES_TO),
                pattern=re.compile(entry["pattern"]),
                action=entry["action"],
                severity=SEVERITY_BY_CATEGORY.get(entry["category"], "high"),
                guidance=entry.get("guidance", ""),
                tests=dict(entry.get("tests") or {}),
            )
        )
    return Feed(feed_version=str(doc.get("feed_version")), signatures=tuple(sigs))
