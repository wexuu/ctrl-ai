"""Semantic-outage mode: both circuits open, or security on-call's manual switch.

While in outage the gateway skips Jev and the judge; deterministic controls stay on.
``degrade`` allows and flags every request (``semantic.reason: outage``); ``fail_closed``
refuses with 503. Transitions write ``incident`` rows once, never per request.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from ctrl_ai.core.audit import utc_now_iso
from ctrl_ai.core.schema import validate
from ctrl_ai.semantic.circuit import Breaker

FAIL_CLOSED_MESSAGE = (
    "ctrl-ai: semantic checks are unavailable and policy requires them; "
    "try again shortly or contact AI platform on-call."
)
DEFAULTS = {
    "mode": "degrade",
    "strict_profiles_fail_closed": True,
    "circuit": {"failures_to_open": 5, "window_s": 60, "cooldown_s": 30},
    "max_manual_minutes": 120,
}


def parse_register(raw: bytes) -> dict:
    doc = json.loads(raw.decode("utf-8"))
    validate(doc, "break_glass")
    return doc


def incident_row(
    event: str, component: str, mode: str | None, reason: str, by: str = "gateway", **extra
) -> dict:
    row = {
        "type": "incident",
        "v": 2,
        "ts": utc_now_iso(),
        "event": event,
        "component": component,
        "mode": mode,
        "reason": reason,
        "by": by,
    }
    row.update({k: v for k, v in extra.items() if v is not None})
    return row


def _parse_time(value: Any) -> datetime | None:
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return when if when.tzinfo else when.replace(tzinfo=UTC)
    except ValueError:
        return None


class OutageMonitor:
    def __init__(self, write: Callable[[dict], None] | None = None, *, register: Any, clock=None):
        self.breakers = {"jev": Breaker("jev"), "judge": Breaker("judge")}
        self._write = write
        self._register = register
        self._lock = threading.Lock()
        self._in_outage = False
        self._manual_seen: str | None = None  # issued_at of the manual switch already acted on
        self._manual_ended: str | None = None
        self._now = clock or (lambda: datetime.now(UTC))

    def _emit(self, row: dict) -> None:
        try:
            if self._write:
                self._write(row)
        except Exception:
            pass

    def configure(self, settings: dict) -> None:
        c = {**DEFAULTS["circuit"], **(settings.get("circuit") or {})}
        for b in self.breakers.values():
            b.configure(int(c["failures_to_open"]), int(c["window_s"]), int(c["cooldown_s"]))

    def manual(self) -> dict | None:
        """The active, unexpired manual switch, or None. Expiry is reported once (manual_off)."""
        try:
            entry = (self._register.current() or {}).get("semantic_outage")
        except Exception:
            entry = None
        if not entry or not entry.get("active"):
            return None
        key = f"{entry.get('issued_at')}|{entry.get('mode')}"
        expires = _parse_time(entry.get("expires_at"))
        if expires is not None and expires <= self._now():
            if self._manual_ended != key:
                self._manual_ended = key
                self._emit(incident_row("manual_off", "semantic", entry.get("mode"), "expired", "gateway"))
            return None
        if self._manual_seen != key:
            self._manual_seen = key
            if entry.get("mode") == "normal":
                for name, b in self.breakers.items():
                    if b.force_close() == "close":
                        self._emit(
                            incident_row(
                                "close",
                                name,
                                None,
                                "manual switch: normal",
                                entry.get("issued_by") or "manual",
                            )
                        )
        return entry

    def status(self, settings: dict) -> dict:
        """{"outage": bool, "mode": degrade|fail_closed|None, "source": manual|circuit|None}."""
        self.configure(settings)
        entry = self.manual()
        if entry is not None and entry.get("mode") in ("degrade", "fail_closed"):
            out = {"outage": True, "mode": entry["mode"], "source": "manual"}
        elif entry is not None and entry.get("mode") == "normal":
            out = {"outage": False, "mode": None, "source": "manual"}
        elif all(b.is_open for b in self.breakers.values()):
            out = {"outage": True, "mode": settings.get("mode", "degrade"), "source": "circuit"}
        else:
            out = {"outage": False, "mode": None, "source": None}
        self._transition(out)
        return out

    def _transition(self, out: dict) -> None:
        with self._lock:
            if out["outage"] == self._in_outage:
                return
            self._in_outage = out["outage"]
        if out["outage"]:
            reason = "manual switch" if out["source"] == "manual" else "jev and judge circuits open"
            self._emit(incident_row("outage_start", "semantic", out["mode"], reason))
        else:
            self._emit(
                incident_row(
                    "outage_end",
                    "semantic",
                    None,
                    "manual switch" if out["source"] == "manual" else "a semantic check recovered",
                )
            )

    def allow(self, component: str) -> bool:
        return self.breakers[component].allow()

    def record(self, component: str, success: bool, reason: str = "") -> None:
        event = self.breakers[component].record(success, reason)
        if event == "open":
            self._emit(incident_row("open", component, None, self.breakers[component].last_reason))
        elif event == "close":
            self._emit(incident_row("close", component, None, "probe succeeded"))
