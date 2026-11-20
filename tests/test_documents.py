"""Tests for the documents source (downloads served by respx)."""

from __future__ import annotations

from dataclasses import replace

import httpx
import respx

from osint_recon.config import Config
from osint_recon.models import Findings
from osint_recon.sources.documents import DocumentsSource
from tests.conftest import MakeCtx
from tests.docfactory import make_docx, make_pdf

BASE = "https://example.com/files"


def links(*names: str) -> Findings:
    return Findings(document_links=[f"{BASE}/{n}" for n in names])


async def test_documents_people_and_software(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(f"{BASE}/report.pdf").mock(
        return_value=httpx.Response(
            200,
            content=make_pdf(
                {"/Author": "John Doe", "/Creator": "LibreOffice 7.6",
                 "/Producer": "LibreOffice 7.6"}  # same value twice: listed once
            ),
        )
    )
    respx_mock.get(f"{BASE}/policy.docx").mock(
        return_value=httpx.Response(200, content=make_docx(creator="Jane Smith",
                                                           modified_by="Administrator"))
    )
    ctx = make_ctx(previous=links("report.pdf", "policy.docx"))

    found = await DocumentsSource().collect(ctx)

    assert len(found.documents) == 2
    assert sorted(p.name for p in found.people) == ["Jane Smith", "John Doe"]  # no "Administrator"
    assert all(p.sources == ("documents",) for p in found.people)
    assert {t.name for t in found.technologies} == {"LibreOffice 7.6",
                                                    "Microsoft Office Word 16.0000"}
    assert "2 of 2 document(s) analysed" in ctx.notes


async def test_problems_are_counted_not_fatal(
    make_ctx: MakeCtx, respx_mock: respx.MockRouter, config: Config
) -> None:
    respx_mock.get(f"{BASE}/ok.pdf").mock(return_value=httpx.Response(200, content=make_pdf()))
    respx_mock.get(f"{BASE}/huge.pdf").mock(
        return_value=httpx.Response(200, content=b"%PDF" + b"0" * 3_000_000)
    )
    respx_mock.get(f"{BASE}/gone.pdf").mock(return_value=httpx.Response(404))
    respx_mock.get(f"{BASE}/fake.pdf").mock(return_value=httpx.Response(200, text="<html>"))
    cfg = replace(config, crawl=replace(config.crawl, max_document_mb=1))
    ctx = make_ctx(previous=links("ok.pdf", "huge.pdf", "gone.pdf", "fake.pdf"), cfg=cfg)

    found = await DocumentsSource().collect(ctx)

    assert len(found.documents) == 1
    (note,) = ctx.notes
    assert "1 of 4 document(s) analysed" in note
    assert "1 over 1 MB" in note and "1 failed to download" in note
    assert "1 unsupported or corrupt" in note


async def test_max_documents(make_ctx: MakeCtx, respx_mock: respx.MockRouter,
                             config: Config) -> None:
    route = respx_mock.get(url__startswith=BASE).mock(
        return_value=httpx.Response(200, content=make_pdf())
    )
    cfg = replace(config, crawl=replace(config.crawl, max_documents=2))
    ctx = make_ctx(previous=links("a.pdf", "b.pdf", "c.pdf"), cfg=cfg)
    found = await DocumentsSource().collect(ctx)
    assert route.call_count == 2 and len(found.documents) == 2
    assert any("first 2 of 3" in n for n in ctx.notes)


async def test_no_links(make_ctx: MakeCtx) -> None:
    ctx = make_ctx()
    assert (await DocumentsSource().collect(ctx)).count() == 0
    assert ctx.notes == ["no public documents were found by the crawler"]
