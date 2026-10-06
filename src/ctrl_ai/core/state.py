"""Shared state in Redis: a small async wrapper that fails open.

Lazily connected to the URL it is given (``CTRL_AI_REDIS_URL`` in the settings); no URL means
no shared state. Every call has a 200 ms timeout; any error raises
``StateUnavailable`` so callers can record "unavailable" and let the request through.
The gateway starts and serves without Redis, and picks it up when it appears.
"""

from __future__ import annotations

import asyncio
from typing import Any

TIMEOUT_S = 0.2


class StateUnavailable(Exception):
    """Redis is not reachable or too slow."""


class RedisState:
    def __init__(self, url: str = ""):
        self._url = url
        self._client: Any = None

    def _redis(self):
        if not self._url:
            raise StateUnavailable("no_url")
        if self._client is None:
            try:
                import redis.asyncio as aioredis
            except ImportError:
                raise StateUnavailable("no_library") from None
            self._client = aioredis.from_url(
                self._url, socket_timeout=TIMEOUT_S, socket_connect_timeout=TIMEOUT_S, decode_responses=True
            )
        return self._client

    async def _run(self, make):
        try:
            return await asyncio.wait_for(make(self._redis()), timeout=TIMEOUT_S)
        except StateUnavailable:
            raise
        except Exception as exc:
            raise StateUnavailable(type(exc).__name__) from None

    async def incr(self, key: str, ttl: int) -> int:
        async def op(r):
            async with r.pipeline(transaction=True) as p:
                p.incr(key)
                p.expire(key, ttl)
                out = await p.execute()
            return int(out[0])

        return await self._run(op)

    async def incrby(self, key: str, amount: int, ttl: int) -> int:
        async def op(r):
            async with r.pipeline(transaction=True) as p:
                p.incrby(key, amount)
                p.expire(key, ttl)
                out = await p.execute()
            return int(out[0])

        return await self._run(op)

    async def incrbyfloat(self, key: str, amount: float, ttl: int) -> float:
        async def op(r):
            async with r.pipeline(transaction=True) as p:
                p.incrbyfloat(key, amount)
                p.expire(key, ttl)
                out = await p.execute()
            return float(out[0])

        return await self._run(op)

    async def get(self, key: str) -> str | None:
        return await self._run(lambda r: r.get(key))

    async def set(self, key: str, value: str, ttl: int) -> None:
        await self._run(lambda r: r.set(key, value, ex=ttl))

    async def push_recent(self, key: str, value: str, keep: int, ttl: int) -> list[str]:
        """Prepend ``value``, keep the newest ``keep`` items, return them (newest first)."""

        async def op(r):
            async with r.pipeline(transaction=True) as p:
                p.lpush(key, value)
                p.ltrim(key, 0, keep - 1)
                p.expire(key, ttl)
                p.lrange(key, 0, keep - 1)
                out = await p.execute()
            return list(out[-1])

        return await self._run(op)

    async def hset_many(self, key: str, mapping: dict[str, str], ttl: int) -> None:
        async def op(r):
            async with r.pipeline(transaction=True) as p:
                p.hset(key, mapping=mapping)
                p.expire(key, ttl)
                await p.execute()

        if mapping:
            await self._run(op)

    async def hgetall(self, key: str) -> dict[str, str]:
        return await self._run(lambda r: r.hgetall(key))
