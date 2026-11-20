"""Per-source asynchronous rate limiter.

Combines two limits, both configurable per source in YAML:

* ``concurrency``: at most N requests in flight (an ``asyncio.Semaphore``);
* ``min_interval``: at least S seconds between the *start* of two requests.

``penalize(seconds)`` pushes the next allowed slot into the future. The HTTP
client calls it when a service answers ``429 Too Many Requests`` with a
``Retry-After``, so the whole source slows down, not just one request.

``clock`` and ``sleep`` are injectable so tests can check the timing without
actually waiting.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from types import TracebackType

Clock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]


class RateLimiter:
    def __init__(
        self,
        min_interval: float = 0.0,
        concurrency: int = 1,
        *,
        clock: Clock = time.monotonic,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be >= 1")
        self.min_interval = max(0.0, min_interval)
        self._semaphore = asyncio.Semaphore(concurrency)
        self._lock = asyncio.Lock()
        self._clock = clock
        self._sleep = sleep
        self._next_slot = 0.0

    async def __aenter__(self) -> None:
        await self._semaphore.acquire()
        try:
            # The lock serialises slot assignment: waiting requests queue up
            # and leave spaced by min_interval.
            async with self._lock:
                now = self._clock()
                wait = self._next_slot - now
                if wait > 0:
                    await self._sleep(wait)
                self._next_slot = max(now, self._next_slot) + self.min_interval
        except BaseException:
            self._semaphore.release()
            raise

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._semaphore.release()

    def penalize(self, seconds: float) -> None:
        """Do not start another request for ``seconds`` (e.g. after a 429)."""
        self._next_slot = max(self._next_slot, self._clock() + seconds)
