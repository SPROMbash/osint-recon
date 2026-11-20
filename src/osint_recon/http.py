"""HTTP access for sources: one shared ``httpx.AsyncClient``, one limiter per source.

:class:`HttpClient` adds what every source needs on top of httpx:

* waits for its source's :class:`RateLimiter` before each request;
* retries on ``429``, ``5xx`` and network errors with exponential backoff,
  honouring ``Retry-After`` (seconds or HTTP date) up to ``max_retry_wait``;
* turns failures into :class:`SourceError` with an actionable message;
* never logs query strings (they may contain API keys) — and the logging
  ``SecretFilter`` masks keys anyway, as a second line of defence;
* downloads with a size cap (streaming), for public documents.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from osint_recon.config import Config
from osint_recon.errors import SourceError
from osint_recon.log import get_logger
from osint_recon.ratelimit import RateLimiter

log = get_logger(__name__)

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
Params = Mapping[str, str | int]


def make_async_client(config: Config) -> httpx.AsyncClient:
    """The single connection pool shared by every source in a run."""
    return httpx.AsyncClient(
        timeout=config.http.timeout,
        headers={"User-Agent": config.http.user_agent},
        follow_redirects=True,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )


class HttpClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        limiter: RateLimiter,
        *,
        source: str,
        max_retries: int = 3,
        max_retry_wait: float = 120.0,
        backoff_base: float = 1.0,
    ) -> None:
        self.client = client
        self.limiter = limiter
        self.source = source
        self.max_retries = max_retries
        self.max_retry_wait = max_retry_wait
        self.backoff_base = backoff_base

    # ------------------------------------------------------------------ #
    async def get(
        self, url: str, *, params: Params | None = None, headers: Mapping[str, str] | None = None
    ) -> httpx.Response:
        """GET with rate limiting and retries. Non-retryable statuses are returned."""
        last_problem = ""
        last_status: int | None = None
        for attempt in range(self.max_retries + 1):
            async with self.limiter:
                log.debug("[%s] GET %s (attempt %d)", self.source, _safe(url), attempt + 1)
                try:
                    response = await self.client.get(url, params=params, headers=headers)
                except httpx.TransportError as exc:  # DNS failure, refused, timeout...
                    last_problem = f"{type(exc).__name__}"
                    last_status = None
                    delay = self._backoff(attempt)
                else:
                    if response.status_code not in RETRY_STATUSES:
                        return response
                    last_problem = f"HTTP {response.status_code}"
                    last_status = response.status_code
                    delay = self._retry_after(response) or self._backoff(attempt)
                    if delay > self.max_retry_wait:
                        raise SourceError(
                            f"{self.source}: rate limited, asked to wait {delay:.0f}s "
                            f"(more than max_retry_wait={self.max_retry_wait:.0f}s). Try later.",
                            status=response.status_code,
                        )

            if attempt < self.max_retries:
                # The limiter is the single source of truth for waiting: penalising
                # it delays this retry AND every other request of this source.
                log.debug("[%s] %s, retrying in %.1fs", self.source, last_problem, delay)
                self.limiter.penalize(delay)

        raise SourceError(
            f"{self.source}: giving up after {self.max_retries + 1} attempts ({last_problem})",
            status=last_status,
        )

    async def get_json(
        self, url: str, *, params: Params | None = None, headers: Mapping[str, str] | None = None
    ) -> Any:
        response = await self.get(url, params=params, headers=headers)
        check_status(response, self.source)
        try:
            return response.json()
        except ValueError:
            raise SourceError(f"{self.source}: response is not valid JSON") from None

    async def get_bytes(self, url: str, *, max_bytes: int) -> bytes | None:
        """Download at most ``max_bytes`` (streaming). ``None`` if the file is bigger."""
        async with self.limiter:
            log.debug("[%s] GET %s (download)", self.source, _safe(url))
            try:
                async with self.client.stream("GET", url) as response:
                    check_status(response, self.source)
                    declared = response.headers.get("Content-Length", "")
                    if declared.isdigit() and int(declared) > max_bytes:
                        return None
                    buffer = bytearray()
                    async for chunk in response.aiter_bytes():
                        buffer.extend(chunk)
                        if len(buffer) > max_bytes:  # server lied or sent no length
                            return None
                    return bytes(buffer)
            except httpx.TransportError as exc:
                reason = type(exc).__name__
                raise SourceError(f"{self.source}: download failed ({reason})") from None

    # ------------------------------------------------------------------ #
    def _backoff(self, attempt: int) -> float:
        return float(self.backoff_base * (2**attempt))

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        value = response.headers.get("Retry-After", "").strip()
        if not value:
            return None
        if value.replace(".", "", 1).isdigit():
            return float(value)
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def check_status(response: httpx.Response, source: str) -> None:
    """Raise a clear :class:`SourceError` for HTTP errors."""
    code = response.status_code
    if code < 400:
        return
    if code in (401, 403):
        raise SourceError(f"{source}: access denied (HTTP {code}). Check the API key / plan.")
    if code == 404:
        raise SourceError(f"{source}: not found (HTTP 404)")
    raise SourceError(f"{source}: HTTP {code}")


def _safe(url: str) -> str:
    """URL without query string (it may carry an API key)."""
    return url.split("?", 1)[0]
