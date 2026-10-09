"""Circuit breakers for the third-party semantic checks. Pure; the clock is injectable.

closed: calls go through; ``failures_to_open`` failures within ``window_s`` open it.
open: calls are skipped at once (verdict ``error: circuit_open``); after ``cooldown_s`` one
probe is let through (half-open). The probe's success closes it, its failure re-opens it.
State is per gateway process; it is not shared through Redis yet.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class Breaker:
    def __init__(
        self,
        component: str,
        failures_to_open: int = 5,
        window_s: int = 60,
        cooldown_s: int = 30,
        clock=time.monotonic,
    ):
        self.component = component
        self.failures_to_open, self.window_s, self.cooldown_s = failures_to_open, window_s, cooldown_s
        self._clock = clock
        self._failures: deque[float] = deque()
        self.state = "closed"
        self._opened_at = 0.0
        self._probe = False
        self._lock = threading.Lock()
        self.last_reason = ""

    def configure(self, failures_to_open: int, window_s: int, cooldown_s: int) -> None:
        self.failures_to_open, self.window_s, self.cooldown_s = failures_to_open, window_s, cooldown_s

    @property
    def is_open(self) -> bool:
        return self.state != "closed"

    def allow(self) -> bool:
        """May a call go out now? In the open state only the one probe after the cooldown."""
        with self._lock:
            if self.state == "closed":
                return True
            if not self._probe and self._clock() - self._opened_at >= self.cooldown_s:
                self.state, self._probe = "half_open", True
                return True
            return False

    def record(self, success: bool, reason: str = "") -> str | None:
        """Record a call's outcome; return ``open`` or ``close`` when the state changes."""
        with self._lock:
            now = self._clock()
            if success:
                was_open = self.state != "closed"
                self.state, self._probe = "closed", False
                self._failures.clear()
                return "close" if was_open else None
            if self.state != "closed":  # a failed probe: open again, new cooldown
                self.state, self._probe, self._opened_at = "open", False, now
                return None
            self._failures.append(now)
            while self._failures and now - self._failures[0] > self.window_s:
                self._failures.popleft()
            if len(self._failures) >= self.failures_to_open:
                self.state, self._opened_at, self._probe = "open", now, False
                self.last_reason = f"{len(self._failures)} failures in {self.window_s}s" + (
                    f" ({reason})" if reason else ""
                )
                self._failures.clear()
                return "open"
            return None

    def force_close(self) -> str | None:
        with self._lock:
            was_open = self.state != "closed"
            self.state, self._probe = "closed", False
            self._failures.clear()
            return "close" if was_open else None
