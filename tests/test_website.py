"""Tests for the polite website crawler, against a fake site served by respx."""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
import respx

from osint_recon.config import Config
from osint_recon.errors import SourceError
from osint_recon.sources.website import WebsiteSource
from tests.conftest import MakeCtx

SITE = "https://example.com"

ROBOTS = """
User-agent: *
Disallow: /private/
Disallow: /files/secret.pdf
"""

HOME = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.6.2">
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head><body>
<a href="/about">About</a>
<a href="/about#team">About again (fragment)</a>
<a href="/private/admin">Private</a>
<a href="/files/report-2026.pdf">Annual report</a>
<a href="/files/secret.pdf">Disallowed doc</a>
<a href="https://shop.example.com/">Shop</a>
<a href="https://twitter.com/example">Twitter</a>
<a href="mailto:Info@Example.com?subject=Hi">Contact</a>
<a href="javascript:void(0)">js</a>
<img src="/logo@2x.png">
</body></html>"""

ABOUT = """<html><body>
<p>Press: press@example.com - partner: someone@partner.org</p>
<a href="https://cdn.example.com/docs/policy.docx">Policy</a>
<a href="/about/deeper">Too deep for max_depth=1</a>
</body></html>"""

HTML = {"Content-Type": "text/html; charset=utf-8"}


def html(body: str, **headers: str) -> httpx.Response:
    return httpx.Response(200, text=body, headers={**HTML, **headers})


@pytest.fixture()
def shallow(config: Config) -> Config:
    return replace(config, crawl=replace(config.crawl, max_depth=1, max_pages=10))


def mount_site(respx_mock: respx.MockRouter) -> dict[str, respx.Route]:
    return {
        "robots": respx_mock.get(f"{SITE}/robots.txt").mock(
            return_value=httpx.Response(200, text=ROBOTS)
        ),
        "home": respx_mock.get(f"{SITE}/").mock(
            return_value=html(
                HOME,
                Server="nginx/1.25.3",
                **{"X-Powered-By": "PHP/8.2.12", "Set-Cookie": "PHPSESSID=abc; path=/"},
            )
        ),
        "about": respx_mock.get(f"{SITE}/about").mock(return_value=html(ABOUT)),
        "private": respx_mock.get(f"{SITE}/private/admin").mock(return_value=html("secret")),
        "deeper": respx_mock.get(f"{SITE}/about/deeper").mock(return_value=html("deep")),
    }


async def test_crawl_collects_everything_politely(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, shallow: Config
) -> None:
    routes = mount_site(respx_mock)
    ctx = make_ctx(cfg=shallow)

    found = await WebsiteSource().collect(ctx)

    # politeness
    assert routes["private"].call_count == 0  # Disallow: /private/
    assert routes["deeper"].call_count == 0  # beyond max_depth
    assert routes["about"].call_count == 1  # "/about#team" is the same page
    # findings
    techs = {t.name: t.version for t in found.technologies}
    assert techs["nginx"] == "1.25.3" and techs["PHP"] == "8.2.12"
    assert techs["WordPress"] == "6.6.2" and "jQuery" in techs
    assert sorted(e.address for e in found.emails) == ["info@example.com", "press@example.com"]
    assert found.document_links == [
        "https://example.com/files/report-2026.pdf",  # secret.pdf excluded by robots.txt
        "https://cdn.example.com/docs/policy.docx",  # other subdomain of the target: kept
    ]
    assert {s.name for s in found.subdomains} >= {"shop.example.com", "cdn.example.com"}
    assert "twitter.com" not in {s.name for s in found.subdomains}
    assert any("2 page(s) crawled" in n and "1 blocked by robots.txt" in n for n in ctx.notes)


async def test_max_pages_is_respected(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config
) -> None:
    routes = mount_site(respx_mock)
    ctx = make_ctx(cfg=replace(config, crawl=replace(config.crawl, max_pages=1)))
    await WebsiteSource().collect(ctx)
    assert routes["about"].call_count == 0
    assert any("stopped at crawl.max_pages=1" in n for n in ctx.notes)


async def test_missing_robots_allows_crawl(make_ctx: MakeCtx, respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{SITE}/robots.txt").mock(return_value=httpx.Response(404))
    respx_mock.get(f"{SITE}/").mock(return_value=html("<a href='/x.pdf'>doc</a>"))
    found = await WebsiteSource().collect(make_ctx())
    assert found.document_links == ["https://example.com/x.pdf"]


async def test_robots_server_error_means_no_crawl(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{SITE}/robots.txt").mock(return_value=httpx.Response(503))
    home = respx_mock.get(f"{SITE}/").mock(return_value=html("x"))
    www = respx_mock.get("https://www.example.com/robots.txt").mock(
        return_value=httpx.Response(404)
    )
    with pytest.raises(SourceError, match="RFC 9309"):
        await WebsiteSource().collect(make_ctx())
    assert home.call_count == 0
    assert www.call_count == 0  # a failing server is NOT a reason to try another origin


async def test_robots_non_retryable_server_error(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{SITE}/robots.txt").mock(return_value=httpx.Response(501))
    with pytest.raises(SourceError, match="HTTP 501"):
        await WebsiteSource().collect(make_ctx())


async def test_falls_back_to_www(make_ctx: MakeCtx, respx_mock: respx.MockRouter) -> None:
    respx_mock.get(f"{SITE}/robots.txt").mock(side_effect=httpx.ConnectError("no apex"))
    respx_mock.get("https://www.example.com/robots.txt").mock(return_value=httpx.Response(404))
    respx_mock.get("https://www.example.com/").mock(return_value=html("<p>hi</p>"))
    ctx = make_ctx()
    await WebsiteSource().collect(ctx)
    assert any("from https://www.example.com" in n for n in ctx.notes)


async def test_unreachable_site(make_ctx: MakeCtx, respx_mock: respx.MockRouter) -> None:
    respx_mock.route(path="/robots.txt").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(SourceError, match="not reachable"):
        await WebsiteSource().collect(make_ctx())


async def test_offsite_redirect_and_non_html_are_ignored(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{SITE}/robots.txt").mock(return_value=httpx.Response(404))
    respx_mock.get(f"{SITE}/").mock(
        return_value=html("<a href='/feed'>feed</a><a href='/gone'>gone</a><a href='/out'>o</a>")
    )
    respx_mock.get(f"{SITE}/feed").mock(
        return_value=httpx.Response(200, text="{}", headers={"Content-Type": "application/json"})
    )
    respx_mock.get(f"{SITE}/gone").mock(return_value=httpx.Response(404, headers=HTML))
    respx_mock.get(f"{SITE}/out").mock(
        return_value=httpx.Response(302, headers={"Location": "https://elsewhere.net/"})
    )
    respx_mock.get("https://elsewhere.net/").mock(return_value=html("<p>x@example.com</p>"))

    ctx = make_ctx()
    found = await WebsiteSource().collect(ctx)

    assert found.emails == []  # the off-site page was not processed
    assert any("1 page(s) crawled" in n for n in ctx.notes)


async def test_page_failure_does_not_stop_crawl(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{SITE}/robots.txt").mock(return_value=httpx.Response(404))
    respx_mock.get(f"{SITE}/").mock(return_value=html("<a href='/a'>a</a><a href='/b'>b</a>"))
    respx_mock.get(f"{SITE}/a").mock(side_effect=httpx.ReadTimeout("slow"))
    respx_mock.get(f"{SITE}/b").mock(return_value=html("<p>team@example.com</p>"))

    ctx = make_ctx()
    found = await WebsiteSource().collect(ctx)

    assert [e.address for e in found.emails] == ["team@example.com"]
    assert any("1 failed" in n for n in ctx.notes)
