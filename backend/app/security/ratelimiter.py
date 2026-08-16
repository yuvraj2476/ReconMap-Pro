"""Async token-bucket rate limiter.

Uses Redis when available (shared across workers), otherwise falls back to an
in-process implementation. This keeps scanning polite and prevents accidental
flooding of a target.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class _InMemoryBucket:
    tokens: float
    updated: float


class InMemoryRateLimiter:
    """Simple token bucket per key."""

    def __init__(self, rate_per_sec: float = 2.0, burst: int = 5) -> None:
        self.rate = rate_per_sec
        self.burst = burst
        self._buckets: dict[str, _InMemoryBucket] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, key: str = "global") -> None:
        async with self._lock:
            now = time.monotonic()
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _InMemoryBucket(tokens=float(self.burst), updated=now)
                self._buckets[key] = bucket
            # Refill
            elapsed = now - bucket.updated
            bucket.tokens = min(float(self.burst), bucket.tokens + elapsed * self.rate)
            bucket.updated = now

            if bucket.tokens < 1:
                wait = (1 - bucket.tokens) / self.rate
                await asyncio.sleep(wait)
                bucket.tokens = 0
            else:
                bucket.tokens -= 1


class RedisRateLimiter:  # pragma: no cover - requires live redis
    """Token-bucket limiter backed by a Lua script in Redis."""

    _LUA = """
    local key = KEYS[1]
    local rate = tonumber(ARGV[1])
    local burst = tonumber(ARGV[2])
    local now = tonumber(ARGV[3])
    local data = redis.call('HMGET', key, 'tokens', 'updated')
    local tokens = tonumber(data[1]) or burst
    local updated = tonumber(data[2]) or now
    tokens = math.min(burst, tokens + (now - updated) * rate)
    local wait = 0
    if tokens < 1 then
        wait = (1 - tokens) / rate
        tokens = 0
    else
        tokens = tokens - 1
    end
    redis.call('HMSET', key, 'tokens', tokens, 'updated', now)
    redis.call('EXPIRE', key, 60)
    return wait
    """

    def __init__(self, redis_url: str, rate_per_sec: float = 2.0, burst: int = 5) -> None:
        import redis.asyncio as aioredis  # type: ignore

        self._redis = aioredis.from_url(redis_url)
        self.rate = rate_per_sec
        self.burst = burst

    async def acquire(self, key: str = "global") -> None:
        wait = await self._redis.eval(
            self._LUA, 1, f"ratelimit:{key}", self.rate, self.burst, time.time()
        )
        if wait and float(wait) > 0:
            await asyncio.sleep(float(wait))


def build_rate_limiter(redis_url: Optional[str], rate_per_sec: float = 2.0, burst: int = 5):
    if redis_url:
        try:  # pragma: no cover
            return RedisRateLimiter(redis_url, rate_per_sec, burst)
        except Exception:
            pass
    return InMemoryRateLimiter(rate_per_sec, burst)
