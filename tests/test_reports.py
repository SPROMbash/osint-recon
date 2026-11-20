"""Tests for Markdown/JSON rendering, redaction and atomic writing."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from osint_recon.models import (
    Breach,
    DocumentMeta,
    Email,
    Findings,
    Person,
    Report,
    SourceResult,
    Subdomain,
    Technology,
)
from osint_recon.report.json_report import SCHEMA, render_json
from osint_recon.report.markdown import render_markdown
from osint_recon.report.redact import initials, mask_email, redact_report
from osint_recon.report.writer import atomic_write, report_basename, write_reports

WHEN = datetime(2026, 11, 20, 12, 30, 0, tzinfo=timezone.utc)


def sample(**overrides: Any) -> Report:
    findings = Findings(
        subdomains=[Subdomain("www.example.com", ("crtsh", "dns"), ("93.184.215.14",))],
        emails=[Email("jane.smith@example.com", ("hunter",), "Jane Smith", "CTO")],
        people=[Person("Jane Smith", ("hunter", "documents"), "CTO")],
        technologies=[Technology("nginx", "Web server", ("website",), "1.25.3",
                                 ("header server: nginx/1.25.3",))],
        documents=[DocumentMeta("https://example.com/a.pdf", "pdf", 1234, author="Jane Smith",
                                last_modified_by="jsmith", software="Word | 2019",
                                created=WHEN)],
        breaches=[
            Breach("ExampleCorp", "service", "Example Corp", "2023-04-11", 120345,
                   ("Email addresses", "Passwords")),
            Breach("Adobe", "domain-accounts", "Adobe", "2013-10-04", 152445165,
                   ("Passwords",), ("jane.smith@example.com",)),
        ],
        document_links=["https://example.com/a.pdf"],
    )
    base = Report(
        target="example.com", kind="domain", generated=WHEN, tool_version="0.1.0",
        active=True,
        sources=(SourceResult("crtsh", "ok", "", 1.2, 1),
                 SourceResult("hunter", "skipped", "needs an API key"),
                 SourceResult("otx", "error", "otx: HTTP 500")),
        findings=findings,
    )
    return replace(base, **overrides)


def test_markdown_sections_and_escaping() -> None:
    md = render_markdown(sample())
    assert md.startswith("# OSINT report: example.com\n")
    for heading in ("## Summary", "## Sources", "## Subdomains", "## Emails", "## People",
                    "## Technologies", "## Documents", "## Breaches"):
        assert heading in md
    assert "| www.example.com | 93.184.215.14 | crtsh, dns |" in md
    assert "| otx | **error** | 0 | 0.0s | otx: HTTP 500 |" in md
    assert "Word \\| 2019" in md  # pipe escaped inside a table cell
    assert "### Breaches of the service at this domain" in md
    assert "152,445,165" in md
    assert "public** sources" in md  # ethical note
    assert "passive + active" in md


def test_markdown_empty_and_partial() -> None:
    md = render_markdown(sample(findings=Findings(), partial=True, active=False))
    assert "PARTIAL REPORT" in md
    assert "passive only" in md
    assert md.count("_None found._") == 6


def test_footprint_markdown_has_no_domain_sections() -> None:
    report = sample(kind="footprint", target="footprint", findings=Findings(
        breaches=[Breach("Adobe", "owned-account", affected=("me@example.com",))]))
    md = render_markdown(report)
    assert md.startswith("# Digital footprint")
    assert "## Subdomains" not in md
    assert "### Your own addresses found in breaches" in md


def test_json_is_complete_and_stable() -> None:
    data = json.loads(render_json(sample()))
    assert data["schema"] == SCHEMA
    assert data["target"] == "example.com" and data["generated"] == "2026-11-20T12:30:00+00:00"
    assert data["summary"] == {"subdomains": 1, "emails": 1, "people": 1, "technologies": 1,
                               "documents": 1, "breaches": 2}
    assert "document_links" not in data["findings"]
    assert data["findings"]["documents"][0]["created"] == "2026-11-20T12:30:00+00:00"
    assert data["sources"][2] == {"source": "otx", "status": "error", "message": "otx: HTTP 500",
                                  "duration": 0.0, "findings": 0}


@pytest.mark.parametrize(
    ("raw", "masked"),
    [("jane.smith@example.com", "j***@example.com"), ("@x.com", "***@x.com"),
     ("Jane Smith", "J. S.")],
)
def test_mask_email(raw: str, masked: str) -> None:
    assert mask_email(raw) == masked


def test_initials() -> None:
    assert initials("jane  van der smith") == "J. V. D. S."
    assert initials("J.Smith") == "J. S."
    assert initials("") == ""


def test_redact_report_masks_people_everywhere() -> None:
    original = sample()
    redacted = redact_report(original)
    text = render_markdown(redacted) + render_json(redacted)

    assert "Jane Smith" not in text and "jane.smith" not in text and "jsmith" not in text
    assert "j***@example.com" in text and "J. S." in text
    assert "CTO" in text  # positions describe the organisation: kept
    assert redacted.redacted and "Personal data:** redacted" in render_markdown(redacted)
    assert original.findings.emails[0].address == "jane.smith@example.com"  # untouched


def test_write_reports(tmp_path: Path) -> None:
    report = sample()
    paths = write_reports(report, tmp_path / "out", ["md", "json"])
    assert [p.name for p in paths] == ["example.com-20261120-123000.md",
                                       "example.com-20261120-123000.json"]
    assert all(p.is_file() for p in paths)
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == sorted(p.name for p in paths)


def test_basename_is_filesystem_safe() -> None:
    assert report_basename(sample(target="Weird/../Name")) == "weird-..-name-20261120-123000"
    assert report_basename(sample(target="", kind="footprint")).startswith("footprint-")


def test_atomic_write_cleans_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(src: str, dst: str) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("os.replace", boom)
    with pytest.raises(KeyboardInterrupt):
        atomic_write(tmp_path / "r.md", "x")
    assert list(tmp_path.iterdir()) == []
