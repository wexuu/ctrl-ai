"""A dict-backed async stand-in for ctrl_ai.core.state.RedisState (no TTLs)."""

from __future__ import annotations

from ctrl_ai.core.state import StateUnavailable


class FakeState:
    def __init__(self):
        self.data: dict = {}
        self.down = False

    def _check(self):
        if self.down:
            raise StateUnavailable("down")

    async def incr(self, key, ttl):
        return await self.incrby(key, 1, ttl)

    async def incrby(self, key, amount, ttl):
        self._check()
        self.data[key] = int(self.data.get(key, 0)) + amount
        return self.data[key]

    async def incrbyfloat(self, key, amount, ttl):
        self._check()
        self.data[key] = float(self.data.get(key, 0)) + amount
        return self.data[key]

    async def get(self, key):
        self._check()
        value = self.data.get(key)
        return None if value is None else str(value)

    async def set(self, key, value, ttl):
        self._check()
        self.data[key] = value

    async def push_recent(self, key, value, keep, ttl):
        self._check()
        items = [value, *list(self.data.get(key, []))]
        self.data[key] = items[:keep]
        return list(self.data[key])

    async def hset_many(self, key, mapping, ttl):
        self._check()
        self.data.setdefault(key, {}).update(mapping)

    async def hgetall(self, key):
        self._check()
        return dict(self.data.get(key, {}))
