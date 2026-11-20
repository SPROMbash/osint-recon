"""Tests for technology fingerprinting rules."""

from __future__ import annotations

import pytest

from osint_recon.errors import ConfigError
from osint_recon.sources.techdetect import PageSignals, default_rules, detect, parse_rules


def names(page: PageSignals) -> dict[str, str]:
    return {t.name: t.version for t in detect(page)}


def test_bundled_rules_load_and_compile() -> None:
    rules = default_rules()
    assert len(rules) >= 20
    assert len({r.name for r in rules}) == len(rules)  # no duplicate names


def test_headers_cookies_and_versions() -> None:
    page = PageSignals(
        url="https://example.com/",
        headers={"server": "nginx/1.25.3", "x-powered-by": "PHP/8.2.12"},
        cookies=["PHPSESSID"],
    )
    found = names(page)
    assert found["nginx"] == "1.25.3"
    assert found["PHP"] == "8.2.12"
    php = next(t for t in detect(page) if t.name == "PHP")
    assert "cookie PHPSESSID" in php.evidence and php.sources == ("website",)


def test_cms_from_generator_and_html() -> None:
    page = PageSignals(
        url="https://example.com/",
        generators=["WordPress 6.6.2"],
        scripts=["https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
                 "https://cdn.example.com/js/bootstrap-5.3.2.bundle.min.js"],
        html='<link href="/wp-content/themes/x/style.css">',
    )
    found = names(page)
    assert found["WordPress"] == "6.6.2"
    assert "jQuery" in found
    assert found["Bootstrap"] == "5.3.2"


def test_no_false_positive_on_plain_page() -> None:
    assert detect(PageSignals(url="https://example.com/", html="<html>hello</html>")) == []


def test_express_requires_exact_header() -> None:
    assert "Express" in names(PageSignals(url="u", headers={"x-powered-by": "Express"}))
    assert "Express" not in names(PageSignals(url="u", headers={"x-powered-by": "ExpressVPN"}))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("name: x\n", "top level must be a list"),
        ("- category: x\n", "needs at least a 'name'"),
        ("- name: x\n  headers: [a]\n", "'headers' must be a mapping"),
        ("- name: x\n  cookies: abc\n", "'cookies' must be a list"),
        ("- name: x\n  html: '(unclosed'\n", "invalid regex"),
    ],
)
def test_invalid_rules(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_rules(text)
