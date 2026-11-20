"""Tests for the HTTP client. respx intercepts httpx: no request leaves the machine."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest
import respx

from osint_recon.config import Config
from osint_recon.errors import SourceError
from osint_recon.http import HttpClient, check_status, make_async_client
from osint_recon.ratelimit import RateLimiter

URL = "https://api.example.test/v1/data"


@pytest.fixture()
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as c:
        yield c


class Sleeps:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(round(seconds, 1))


def make(client: httpx.AsyncClient, sleeps: Sleeps, **kw: float) -> HttpClient:
    # Fake clock that advances only when the limiter "sleeps": exact, instant timing.
    now = [0.0]

    async def fake_sleep(seconds: float) -> None:
        await sleeps(seconds)
        now[0] += seconds

    limiter = RateLimiter(0.0, 1, clock=lambda: now[0], sleep=fake_sleep)
    return HttpClient(
        client, limiter, source="test",
        max_retries=int(kw.get("max_retries", 3)),
        max_retry_wait=kw.get("max_retry_wait", 120.0),
    )


async def test_json_ok(client: httpx.AsyncClient, respx_mock: respx.MockRouter) -> None:
    respx_mock.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
    assert await make(client, Sleeps()).get_json(URL) == {"ok": True}


async def test_retry_on_503_with_exponential_backoff(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(URL).mock(
        side_effect=[httpx.Response(503), httpx.Response(503), httpx.Response(200, json=[1])]
    )
    sleeps = Sleeps()
    assert await make(client, sleeps).get_json(URL) == [1]
    assert route.call_count == 3
    assert sleeps.calls == [1.0, 2.0]  # 1s, 2s, ...


async def test_retry_after_seconds_is_honoured(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(URL).mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200, json=1)]
    )
    sleeps = Sleeps()
    http = make(client, sleeps)
    assert await http.get_json(URL) == 1
    assert 7.0 in sleeps.calls


async def test_retry_after_http_date(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)
    respx_mock.get(URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": when}),
            httpx.Response(200, json=1),
        ]
    )
    sleeps = Sleeps()
    await make(client, sleeps).get_json(URL)
    assert any(25 <= s <= 31 for s in sleeps.calls)


async def test_too_long_retry_after_gives_up(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "3600"}))
    with pytest.raises(SourceError, match="asked to wait 3600s"):
        await make(client, Sleeps()).get(URL)


async def test_gives_up_after_max_retries(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(URL).mock(return_value=httpx.Response(502))
    with pytest.raises(SourceError, match=r"giving up after 3 attempts \(HTTP 502\)") as exc:
        await make(client, Sleeps(), max_retries=2).get(URL)
    assert route.call_count == 3
    assert exc.value.status == 502  # the server answered: callers can tell


async def test_network_failure_has_no_status(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(URL).mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(SourceError) as exc:
        await make(client, Sleeps(), max_retries=0).get(URL)
    assert exc.value.status is None


async def test_network_errors_are_retried(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(URL).mock(
        side_effect=[httpx.ConnectTimeout("slow"), httpx.Response(200, json="ok")]
    )
    assert await make(client, Sleeps()).get_json(URL) == "ok"


async def test_network_error_message_hides_query(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(URL).mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(SourceError) as excinfo:
        await make(client, Sleeps(), max_retries=0).get(URL, params={"api_key": "SECRET123"})
    assert "SECRET123" not in str(excinfo.value)


@pytest.mark.parametrize(
    ("status", "message"),
    [(401, "access denied"), (403, "Check the API key"), (404, "not found"), (418, "HTTP 418")],
)
def test_check_status(status: int, message: str) -> None:
    with pytest.raises(SourceError, match=message):
        check_status(httpx.Response(status), "src")
    check_status(httpx.Response(200), "src")  # no error


async def test_invalid_json(client: httpx.AsyncClient, respx_mock: respx.MockRouter) -> None:
    respx_mock.get(URL).mock(return_value=httpx.Response(200, text="<html>"))
    with pytest.raises(SourceError, match="not valid JSON"):
        await make(client, Sleeps()).get_json(URL)


async def test_download_within_limit(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(URL).mock(return_value=httpx.Response(200, content=b"x" * 100))
    assert await make(client, Sleeps()).get_bytes(URL, max_bytes=1000) == b"x" * 100


async def test_download_too_big_by_header_or_by_content(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(URL).mock(return_value=httpx.Response(200, content=b"x" * 5000))
    assert await make(client, Sleeps()).get_bytes(URL, max_bytes=1000) is None


async def test_download_http_error(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(URL).mock(return_value=httpx.Response(403))
    with pytest.raises(SourceError, match="access denied"):
        await make(client, Sleeps()).get_bytes(URL, max_bytes=10)


async def test_download_network_error(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(URL).mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(SourceError, match="download failed"):
        await make(client, Sleeps()).get_bytes(URL, max_bytes=10)


async def test_client_factory_sets_identity(config: Config) -> None:
    async with make_async_client(config) as c:
        assert c.headers["User-Agent"].startswith("osint-recon/")
        assert c.follow_redirects is True
