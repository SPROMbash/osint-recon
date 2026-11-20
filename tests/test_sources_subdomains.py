"""Tests for the subdomain sources: crt.sh, HackerTarget, OTX and DNS resolution."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import dns.asyncresolver
import dns.resolver
import httpx
import pytest
import respx

from osint_recon.config import Config
from osint_recon.errors import SourceError
from osint_recon.models import Findings, Subdomain
from osint_recon.sources.crtsh import CrtShSource
from osint_recon.sources.dns import DnsSource, Resolve, SystemResolver
from osint_recon.sources.hackertarget import HackerTargetSource
from osint_recon.sources.otx import OtxSource
from tests.conftest import MakeCtx


# --------------------------------------------------------------------------- #
# crt.sh
# --------------------------------------------------------------------------- #
async def test_crtsh_cleans_and_filters(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, fixtures_dir: Path
) -> None:
    route = respx_mock.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, text=(fixtures_dir / "crtsh.json").read_text("utf-8"))
    )

    found = await CrtShSource().collect(make_ctx())

    assert route.calls.last.request.url.params["q"] == "%.example.com"
    assert [s.name for s in found.subdomains] == [
        "dev.example.com",  # "*.dev" and "DEV" collapse into one
        "example.com",
        "mail.example.com",
        "vpn.example.com",
        "www.example.com",  # seen in two certificates, listed once
    ]
    # example-cdn.net (other domain) and admin@example.com (email) were dropped
    assert all(s.sources == ("crtsh",) for s in found.subdomains)


async def test_crtsh_bad_format(make_ctx: MakeCtx, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://crt.sh/").mock(return_value=httpx.Response(200, json={"error": 1}))
    with pytest.raises(SourceError, match="unexpected response format"):
        await CrtShSource().collect(make_ctx())


# --------------------------------------------------------------------------- #
# HackerTarget
# --------------------------------------------------------------------------- #
HT_URL = "https://api.hackertarget.com/hostsearch/"


async def test_hackertarget_parses_hosts_and_ips(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, fixtures_dir: Path
) -> None:
    respx_mock.get(HT_URL).mock(
        return_value=httpx.Response(200, text=(fixtures_dir / "hackertarget.txt").read_text())
    )
    found = await HackerTargetSource().collect(make_ctx())

    by_name = {s.name: s for s in found.subdomains}
    assert set(by_name) == {"example.com", "www.example.com", "api.example.com",
                            "staging.example.com"}  # other-site.org filtered
    assert by_name["api.example.com"].addresses == ("198.51.100.20",)
    assert by_name["staging.example.com"].addresses == ()  # empty IP column tolerated


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("API count exceeded - Increase Quota with Membership", "quota exceeded"),
        ("error check your search parameter", "error check your search"),
    ],
)
async def test_hackertarget_errors_inside_http_200(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, body: str, message: str
) -> None:
    respx_mock.get(HT_URL).mock(return_value=httpx.Response(200, text=body))
    with pytest.raises(SourceError, match=message):
        await HackerTargetSource().collect(make_ctx())


async def test_hackertarget_no_records(make_ctx: MakeCtx, respx_mock: respx.MockRouter) -> None:
    respx_mock.get(HT_URL).mock(return_value=httpx.Response(200, text="No records found"))
    assert (await HackerTargetSource().collect(make_ctx())).count() == 0


# --------------------------------------------------------------------------- #
# OTX
# --------------------------------------------------------------------------- #
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns"


async def test_otx_without_key(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, fixtures_dir: Path
) -> None:
    route = respx_mock.get(OTX_URL).mock(
        return_value=httpx.Response(200, text=(fixtures_dir / "otx_passive_dns.json").read_text())
    )
    found = await OtxSource().collect(make_ctx())

    assert "X-OTX-API-KEY" not in route.calls.last.request.headers
    by_name = {s.name: s for s in found.subdomains}
    assert set(by_name) == {"api.example.com", "blog.example.com"}  # attacker.net filtered
    assert by_name["api.example.com"].addresses == ("198.51.100.20", "2001:db8::10")
    assert by_name["blog.example.com"].addresses == ()  # CNAME target is not an IP


async def test_otx_sends_key_when_configured(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config
) -> None:
    route = respx_mock.get(OTX_URL).mock(return_value=httpx.Response(200, json={"passive_dns": []}))
    cfg = replace(config, api_keys={**config.api_keys, "otx": "otx-key-123456"})
    await OtxSource().collect(make_ctx(cfg=cfg))
    assert route.calls.last.request.headers["X-OTX-API-KEY"] == "otx-key-123456"


async def test_otx_bad_format(make_ctx: MakeCtx, respx_mock: respx.MockRouter) -> None:
    respx_mock.get(OTX_URL).mock(return_value=httpx.Response(200, json=[]))
    with pytest.raises(SourceError, match="unexpected"):
        await OtxSource().collect(make_ctx())


# --------------------------------------------------------------------------- #
# DNS (resolver injected: no real DNS traffic)
# --------------------------------------------------------------------------- #
def fake_resolver(table: dict[str, tuple[str, ...]], wildcard: tuple[str, ...] = ()) -> Resolve:
    """Known names resolve from ``table``; any other name gets the wildcard (or nothing)."""

    async def resolve(name: str) -> tuple[str, ...]:
        return table.get(name, wildcard)

    return resolve


async def test_dns_keeps_only_resolving_hosts(make_ctx: MakeCtx) -> None:
    previous = Findings(subdomains=[Subdomain("www.example.com", ("crtsh",)),
                                    Subdomain("old.example.com", ("crtsh",))])
    ctx = make_ctx(previous=previous)
    ip = ("93.184.215.14",)
    resolve = fake_resolver({"example.com": ip, "www.example.com": ip})

    found = await DnsSource(resolve=resolve).collect(ctx)

    assert [s.name for s in found.subdomains] == ["example.com", "www.example.com"]
    assert found.subdomains[0].sources == ("dns",)
    assert "2 of 3 hosts resolve" in ctx.notes


async def test_dns_wildcard_detection(make_ctx: MakeCtx) -> None:
    previous = Findings(subdomains=[Subdomain("real.example.com", ("crtsh",)),
                                    Subdomain("fake.example.com", ("crtsh",))])
    ctx = make_ctx(previous=previous)
    resolve = fake_resolver({"real.example.com": ("198.51.100.7",)}, wildcard=("203.0.113.9",))

    found = await DnsSource(resolve=resolve).collect(ctx)

    names = [s.name for s in found.subdomains]
    assert "real.example.com" in names
    assert "fake.example.com" not in names  # only resolved to the wildcard IP
    assert any("wildcard DNS detected" in n for n in ctx.notes)


async def test_dns_respects_max_hosts(make_ctx: MakeCtx, config: Config) -> None:
    previous = Findings(subdomains=[Subdomain(f"h{i}.example.com", ("crtsh",)) for i in range(10)])
    ctx = make_ctx(previous=previous, cfg=replace(config, dns_max_hosts=3))
    calls: list[str] = []

    async def resolve(name: str) -> tuple[str, ...]:
        calls.append(name)
        return ()

    await DnsSource(resolve=resolve).collect(ctx)
    assert len(calls) == 1 + 3  # wildcard probe + 3 hosts
    assert any("first 3 of 11" in n for n in ctx.notes)


async def test_system_resolver_handles_missing_records(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeAnswer(list[object]):
        pass

    class Record:
        def __init__(self, text: str) -> None:
            self.text = text

        def to_text(self) -> str:
            return self.text

    async def fake_resolve(self: object, name: str, rtype: str, lifetime: float) -> FakeAnswer:
        if rtype == "AAAA":
            raise dns.resolver.NoAnswer
        return FakeAnswer([Record("192.0.2.1")])

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)
    assert await SystemResolver()("x.example.com") == ("192.0.2.1",)
