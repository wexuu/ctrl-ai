"""A bounded in-process cache of request contexts, keyed by request id.

Passes state between the hooks of one request (pre-call → semantic → post-call →
logger). Entries expire after ten minutes; the oldest are dropped past 10,000. It
holds no credentials; the only text it holds is what masking needs to restore values.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any

MAX_ENTRIES = 10_000
TTL_S = 600.0


class ContextCache:
    def __init__(self, max_entries: int = MAX_ENTRIES, ttl_s: float = TTL_S, clock=time.monotonic):
        self._items: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._max = max_entries
        self._ttl = ttl_s
        self._clock = clock
        self._lock = threading.Lock()

    def put(self, key: str | None, value: Any) -> None:
        if not key:
            return
        with self._lock:
            self._items[key] = (self._clock(), value)
            self._items.move_to_end(key)
            while len(self._items) > self._max:
                self._items.popitem(last=False)

    def get(self, key: str | None) -> Any:
        if not key:
            return None
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            stamp, value = item
            if self._clock() - stamp > self._ttl:
                del self._items[key]
                return None
            return value

    def pop(self, key: str | None) -> Any:
        value = self.get(key)
        if value is not None and key is not None:
            with self._lock:
                self._items.pop(key, None)
        return value

    def __len__(self) -> int:
        return len(self._items)
