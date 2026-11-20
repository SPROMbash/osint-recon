"""Tests for domain validation, ownership checks and the active-collection gate."""

from __future__ import annotations

import pytest

from osint_recon.errors import InvalidTargetError
from osint_recon.scope import (
    active_allowed,
    belongs_to,
    clean_hostname,
    email_belongs_to,
    email_domain,
    normalize_domain,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM. ", "example.com"),
        ("https://www.example.com/path?q=1", "www.example.com"),
        ("example.com:8443", "example.com"),
        ("*.example.com", "example.com"),
        ("bücher.de", "xn--bcher-kva.de"),  # IDNA
    ],
)
def test_normalize_domain(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "localhost", "10.0.0.1", "exa mple.com", "-bad.com", "a..com", "x.123", "a" * 64 + ".com"],
)
def test_normalize_domain_rejects(raw: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_domain(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("*.Dev.Example.com.", "dev.example.com"),
        ("*.*.example.com", "example.com"),
        ("user@example.com", None),
        ("not a host", None),
        ("single", None),
    ],
)
def test_clean_hostname(raw: str, expected: str | None) -> None:
    assert clean_hostname(raw) == expected


def test_belongs_to_is_not_fooled_by_suffixes() -> None:
    assert belongs_to("example.com", "example.com")
    assert belongs_to("a.b.example.com", "example.com")
    assert not belongs_to("badexample.com", "example.com")  # suffix, not subdomain
    assert not belongs_to("example.com.evil.net", "example.com")


def test_emails() -> None:
    assert email_domain("John.Doe@Mail.Example.com") == "mail.example.com"
    assert email_domain("logo@2x.png") is None
    assert email_belongs_to("a@sub.example.com", "example.com")
    assert not email_belongs_to("a@gmail.com", "example.com")


def test_active_gate() -> None:
    assert not active_allowed("example.com", (), authorized_flag=False)
    assert active_allowed("example.com", (), authorized_flag=True)
    assert active_allowed("shop.example.com", ("example.com",), authorized_flag=False)
    assert not active_allowed("example.org", ("example.com",), authorized_flag=False)
