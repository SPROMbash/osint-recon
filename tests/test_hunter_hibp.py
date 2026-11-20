"""Tests for Hunter and Have I Been Pwned, including the ethical guarantees."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from osint_recon.config import Config
from osint_recon.errors import SourceError
from osint_recon.sources.hibp import API, HibpFootprintSource, HibpSource
from osint_recon.sources.hunter import URL as HUNTER_URL
from osint_recon.sources.hunter import HunterSource
from tests.conftest import MakeCtx

HUNTER_KEY = "hunter-key-0123456789"
HIBP_KEY = "hibp-key-0123456789abcdef"


def with_keys(config: Config, **keys: str) -> Config:
    return replace(config, api_keys={**config.api_keys, **keys})


def load(fixtures_dir: Path, name: str) -> Any:
    return json.loads((fixtures_dir / name).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Hunter
# --------------------------------------------------------------------------- #
async def test_hunter_paginates_and_filters(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config, fixtures_dir: Path
) -> None:
    page1 = load(fixtures_dir, "hunter_page1.json")
    route = respx_mock.get(HUNTER_URL).mock(return_value=httpx.Response(200, json=page1))
    cfg = replace(with_keys(config, hunter=HUNTER_KEY), hunter_max_results=13)
    ctx = make_ctx(cfg=cfg)

    found = await HunterSource().collect(ctx)

    first = route.calls[0].request.url.params
    assert first["api_key"] == HUNTER_KEY and first["limit"] == "10" and first["offset"] == "0"
    assert route.call_count == 1  # 3 results < 10 requested: no further page exists
    assert [e.address for e in found.emails] == [
        "jane.smith@example.com", "info@example.com",
    ]  # partner-agency.com is not the target's address
    jane = found.emails[0]
    assert (jane.name, jane.position) == ("Jane Smith", "Chief Technology Officer")
    assert [p.name for p in found.people] == ["Jane Smith"]  # generic inboxes have no person
    assert any("organisation: Example Corp" in n for n in ctx.notes)


async def test_hunter_invalid_key(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config
) -> None:
    respx_mock.get(HUNTER_URL).mock(return_value=httpx.Response(401, json={"errors": []}))
    with pytest.raises(SourceError, match="invalid API key"):
        await HunterSource().collect(make_ctx(cfg=with_keys(config, hunter=HUNTER_KEY)))


async def test_hunter_error_details_without_leaking_key(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config
) -> None:
    body = {"errors": [{"id": "wrong_params", "code": 400, "details": "Invalid domain"}]}
    respx_mock.get(HUNTER_URL).mock(return_value=httpx.Response(400, json=body))
    with pytest.raises(SourceError, match="Invalid domain") as excinfo:
        await HunterSource().collect(make_ctx(cfg=with_keys(config, hunter=HUNTER_KEY)))
    assert HUNTER_KEY not in str(excinfo.value)


async def test_hunter_keeps_first_page_if_later_page_refused(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config, fixtures_dir: Path
) -> None:
    page1 = load(fixtures_dir, "hunter_page1.json")
    page1["meta"]["results"] = 50
    page1["data"]["emails"] = page1["data"]["emails"] * 4  # a full page of 10+ entries
    page1["data"]["emails"] = page1["data"]["emails"][:10]
    respx_mock.get(HUNTER_URL).mock(
        side_effect=[
            httpx.Response(200, json=page1),
            httpx.Response(400, json={"errors": [{"details": "Pagination requires a paid plan"}]}),
        ]
    )
    ctx = make_ctx(cfg=with_keys(config, hunter=HUNTER_KEY))
    found = await HunterSource().collect(ctx)
    assert found.emails  # first page kept
    assert any("stopped at 10 results" in n and "paid plan" in n for n in ctx.notes)


# --------------------------------------------------------------------------- #
# HIBP — domain scan
# --------------------------------------------------------------------------- #
async def test_hibp_without_key_only_checks_the_service(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, fixtures_dir: Path
) -> None:
    service = respx_mock.get(f"{API}/breaches", params={"domain": "example.com"}).mock(
        return_value=httpx.Response(200, json=load(fixtures_dir, "hibp_breaches.json")[:1])
    )
    ctx = make_ctx()

    found = await HibpSource().collect(ctx)

    assert service.call_count == 1
    (breach,) = found.breaches
    assert (breach.name, breach.kind, breach.pwn_count) == ("ExampleCorp", "service", 120345)
    assert breach.data_classes == ("Email addresses", "Names", "Passwords")
    assert breach.affected == ()  # no personal data at all
    assert any("no HIBP API key" in n for n in ctx.notes)


async def test_hibp_with_key_on_verified_domain(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config, fixtures_dir: Path
) -> None:
    catalogue = load(fixtures_dir, "hibp_breaches.json")
    respx_mock.get(f"{API}/breaches", params={"domain": "example.com"}).mock(
        return_value=httpx.Response(200, json=[])
    )
    domain_route = respx_mock.get(f"{API}/breacheddomain/example.com").mock(
        return_value=httpx.Response(
            200, json={"jane.smith": ["Adobe", "LinkedIn"], "info": ["Adobe"]}
        )
    )
    respx_mock.get(f"{API}/breaches", params={}).mock(
        return_value=httpx.Response(200, json=catalogue)
    )
    ctx = make_ctx(cfg=with_keys(config, hibp=HIBP_KEY))

    found = await HibpSource().collect(ctx)

    assert domain_route.calls.last.request.headers["hibp-api-key"] == HIBP_KEY
    by_name = {b.name: b for b in found.breaches}
    assert by_name["Adobe"].kind == "domain-accounts"
    assert by_name["Adobe"].affected == ("info@example.com", "jane.smith@example.com")
    assert by_name["Adobe"].pwn_count == 152445165  # details from the catalogue
    assert by_name["LinkedIn"].affected == ("jane.smith@example.com",)
    assert any("3 account appearance(s) in 2 breach(es)" in n for n in ctx.notes)


async def test_hibp_unverified_domain_is_skipped_with_explanation(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config
) -> None:
    respx_mock.get(f"{API}/breaches").mock(return_value=httpx.Response(200, json=[]))
    respx_mock.get(f"{API}/breacheddomain/example.com").mock(return_value=httpx.Response(403))
    ctx = make_ctx(cfg=with_keys(config, hibp=HIBP_KEY))
    found = await HibpSource().collect(ctx)
    assert found.breaches == []
    assert any("not verified in your HIBP dashboard" in n for n in ctx.notes)


async def test_hibp_domain_with_no_breached_accounts(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config
) -> None:
    respx_mock.get(f"{API}/breaches").mock(return_value=httpx.Response(200, json=[]))
    respx_mock.get(f"{API}/breacheddomain/example.com").mock(return_value=httpx.Response(404))
    ctx = make_ctx(cfg=with_keys(config, hibp=HIBP_KEY))
    await HibpSource().collect(ctx)
    assert any("no accounts of the domain" in n for n in ctx.notes)


async def test_hibp_never_looks_up_individual_emails_in_domain_scan(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config
) -> None:
    respx_mock.get(f"{API}/breaches").mock(return_value=httpx.Response(200, json=[]))
    respx_mock.get(f"{API}/breacheddomain/example.com").mock(return_value=httpx.Response(404))
    account = respx_mock.get(url__startswith=f"{API}/breachedaccount/")
    cfg = with_keys(replace(config, owned_emails=("me@example.com",)), hibp=HIBP_KEY)
    await HibpSource().collect(make_ctx(cfg=cfg))
    assert account.call_count == 0


# --------------------------------------------------------------------------- #
# HIBP — your own footprint
# --------------------------------------------------------------------------- #
async def test_footprint_checks_only_owned_emails(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config, fixtures_dir: Path
) -> None:
    catalogue = load(fixtures_dir, "hibp_breaches.json")
    pwned = respx_mock.get(f"{API}/breachedaccount/me%40example.com").mock(
        return_value=httpx.Response(200, json=catalogue[1:])
    )
    clean = respx_mock.get(f"{API}/breachedaccount/other%40mail.test").mock(
        return_value=httpx.Response(404)
    )
    cfg = with_keys(
        replace(config, owned_emails=("me@example.com", "other@mail.test")), hibp=HIBP_KEY
    )
    ctx = make_ctx(cfg=cfg)

    found = await HibpFootprintSource().collect(ctx)

    assert pwned.call_count == clean.call_count == 1
    assert pwned.calls.last.request.url.params["truncateResponse"] == "false"
    assert [(b.name, b.kind, b.affected) for b in found.breaches] == [
        ("Adobe", "owned-account", ("me@example.com",)),
        ("LinkedIn", "owned-account", ("me@example.com",)),
    ]
    assert "2 address(es) checked, 1 not found in any breach" in ctx.notes


async def test_footprint_bad_key(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config
) -> None:
    respx_mock.get(url__startswith=f"{API}/breachedaccount/").mock(
        return_value=httpx.Response(401)
    )
    cfg = with_keys(replace(config, owned_emails=("me@example.com",)), hibp=HIBP_KEY)
    with pytest.raises(SourceError, match="access denied"):
        await HibpFootprintSource().collect(make_ctx(cfg=cfg))


async def test_hibp_bad_format(make_ctx: MakeCtx, respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{API}/breaches").mock(return_value=httpx.Response(200, json={"x": 1}))
    with pytest.raises(SourceError, match="unexpected"):
        await HibpSource().collect(make_ctx())
