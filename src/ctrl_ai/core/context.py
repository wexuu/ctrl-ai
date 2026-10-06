"""The request context: everything the gateway learns and decides about one request.

Pure data classes. The pre-call hook fills a ``RequestContext``; the semantic hook and
the logger read it back from the context cache (``ctxcache.py``) by request id. It
never holds credentials, and holds text only in ``pieces`` and ``semantic_texts`` (the
semantic texts are already masked where masking applies), which never reach a row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ctrl_ai.core.scores import Score


@dataclass(frozen=True)
class Profile:
    """How strictly a team is treated (policy ``profiles``)."""

    name: str
    mode: str = "enforce"  # enforce | monitor
    semantic_action: str = "observe"  # observe | flag | block
    on_semantic_unavailable: str = "allow"  # allow | flag | block
    description: str = ""


@dataclass(frozen=True)
class Identity:
    """Who is calling: from the caller's gateway key."""

    team: str | None
    department: str | None
    user: str | None
    key_id: str | None
    profile: str | None = None
    error: str | None = None
    mode: str | None = None  # per-team mode; None = the policy decides


ADMIN_IDENTITY = Identity(team="admin", department="platform", user=None, key_id=None, profile=None)


@dataclass(frozen=True)
class Piece:
    """One part of the newest turn, with where it came from."""

    text: str
    source: str  # prompt | tool_result | tool_call
    reminder: bool = False  # Claude Code <system-reminder> content: rules only, never Jev


@dataclass(frozen=True)
class Finding:
    """One rule that matched. Ids and labels only, never the matched text."""

    rule: str
    pack: str  # policy | pii | pl | secrets | signatures | normalisation
    source: str
    action: str  # block | flag | mask
    severity: str

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "pack": self.pack,
            "source": self.source,
            "action": self.action,
            "severity": self.severity,
        }


@dataclass
class RequestContext:
    request_id: str | None = None
    endpoint: str = "unknown"
    model_requested: str | None = None
    model_routed: str | None = None
    stream: bool = False
    identity: Identity = ADMIN_IDENTITY
    profile: Profile = field(default_factory=lambda: Profile(name="default"))
    pieces: list[Piece] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    masked: dict[str, int] = field(default_factory=dict)
    route: str = "external"  # external | claude_subscription
    break_glass: dict | None = None
    loop: dict | None = None
    budget: dict | None = None
    # Texts per source for the semantic check (masked where masking applies).
    semantic_texts: dict[str, str] = field(default_factory=dict)
    session: str | None = None

    # Decision state, filled in as the pipeline runs.
    mode: str | None = None
    policy_version: str | None = None
    decision: str = "allow"  # allow | block | reroute | throttle
    would_block: bool = False
    rule: str | None = None
    route_reason: str | None = None
    data_class_detected: str = "public"
    normalisation: dict = field(
        default_factory=lambda: {"hidden_chars": 0, "tag_chars_decoded": False, "changed": False}
    )
    semantic: dict | None = None
    jev: Score | None = None  # the classifier's answer (the row's "jev" field)
    judge: Score | None = None
    flagged: bool = False
    text_chars: int = 0
    guard_ms: float = 0.0
    error: str | None = None
    message: str | None = None  # text for the client when refused
    status_code: int = 400  # HTTP status when refused
    headers: dict | None = None  # extra response headers when refused (Retry-After)
    # Bookkeeping between hooks (never written to a row).
    row_written: bool = False
    semantic_pending: bool = False
    reserved_usd: float = 0.0
    budget_month: str | None = None
    mask_map: dict[str, str] = field(default_factory=dict, repr=False)
    # Working state of the pipeline. ``policy`` is the Policy the request was decided under
    # (typed as Any: the policy module imports this one).
    policy: Any = None
    route_hint: str | None = None  # the route custom auth recorded, consulted before route_of()
    mask_plan: str | None = None  # rewrite | semantic_only | None
    masking: str | None = None  # why masking did less than planned: no_secret, error: <type>
    restore: str | None = None  # unsupported_stream: rewritten, but the stream cannot be restored
    mask_store: str | None = None  # redis | memory
    outage: dict | None = None  # the semantic-outage status while one is active
    never_relax: frozenset[str] = frozenset()  # rule ids no break-glass override may relax
