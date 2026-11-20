"""Tests for the async rate limiter, using a fake clock (no real waiting)."""

from __future__ import annotations

import asyncio

import pytest

from osint_recon.ratelimit import RateLimiter


class FakeTime:
    """A clock that only advances when someone 'sleeps'."""

    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 3))
        self.now += seconds


async def test_min_interval_spaces_requests() -> None:
    t = FakeTime()
    limiter = RateLimiter(min_interval=2.0, concurrency=5, clock=t.clock, sleep=t.sleep)
    starts: list[float] = []

    async def request() -> None:
        async with limiter:
            starts.append(t.now)

    await asyncio.gather(*(request() for _ in range(4)))

    assert starts == [100.0, 102.0, 104.0, 106.0]
    assert t.sleeps == [2.0, 2.0, 2.0]


async def test_no_wait_when_interval_zero() -> None:
    t = FakeTime()
    limiter = RateLimiter(0.0, 3, clock=t.clock, sleep=t.sleep)
    for _ in range(5):
        async with limiter:
            pass
    assert t.sleeps == []


async def test_concurrency_cap() -> None:
    limiter = RateLimiter(min_interval=0.0, concurrency=2)
    in_flight = 0
    peak = 0

    async def request() -> None:
        nonlocal in_flight, peak
        async with limiter:
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1

    await asyncio.gather(*(request() for _ in range(6)))
    assert peak == 2


async def test_penalize_delays_next_request() -> None:
    t = FakeTime()
    limiter = RateLimiter(min_interval=1.0, concurrency=1, clock=t.clock, sleep=t.sleep)
    async with limiter:
        pass
    limiter.penalize(30.0)  # e.g. Retry-After: 30
    async with limiter:
        pass
    assert t.sleeps == [30.0]


async def test_slot_released_when_cancelled_while_waiting() -> None:
    async def cancelled_sleep(seconds: float) -> None:
        raise asyncio.CancelledError

    limiter = RateLimiter(min_interval=5.0, concurrency=1, sleep=cancelled_sleep)
    async with limiter:  # first request: no wait
        pass
    with pytest.raises(asyncio.CancelledError):
        async with limiter:  # second must wait -> cancelled
            pass
    # the semaphore was released: a new request can still get in
    limiter.min_interval = 0.0
    limiter._next_slot = 0.0
    async with limiter:
        pass


def test_invalid_concurrency() -> None:
    with pytest.raises(ValueError):
        RateLimiter(concurrency=0)
