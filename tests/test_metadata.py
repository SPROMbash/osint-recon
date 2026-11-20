"""Tests for document metadata extraction, using documents built in memory."""

from __future__ import annotations

import io
import zipfile
from datetime import datetime, timezone

import pytest

from osint_recon import metadata
from osint_recon.metadata import extract_metadata, sniff
from tests.docfactory import make_docx, make_pdf

PDF_META = {
    "/Title": "Annual Report 2026",
    "/Author": "John Doe",
    "/Creator": "Microsoft Word 2019",
    "/Producer": "Microsoft: Print To PDF",
    "/CreationDate": "D:20260115103000Z",
    "/ModDate": "D:20260201120000Z",
}


def test_pdf_metadata() -> None:
    meta = extract_metadata("https://example.com/r.pdf", make_pdf(PDF_META))
    assert meta is not None
    assert (meta.filetype, meta.title, meta.author) == ("pdf", "Annual Report 2026", "John Doe")
    assert meta.software == "Microsoft Word 2019 / Microsoft: Print To PDF"
    assert meta.created is not None and meta.created.year == 2026 and meta.created.month == 1
    assert meta.size > 0


def test_pdf_with_empty_user_password_is_still_read() -> None:
    meta = extract_metadata("https://x/a.pdf", make_pdf({"/Author": "Ann"}, user_password=""))
    assert meta is not None and meta.author == "Ann"


def test_pdf_with_real_password_gives_basic_info_only() -> None:
    meta = extract_metadata("https://x/a.pdf", make_pdf({"/Author": "Ann"}, user_password="pw"))
    assert meta is not None
    assert meta.filetype == "pdf" and meta.author == ""


def test_pdf_bad_dates_are_ignored() -> None:
    meta = extract_metadata("https://x/a.pdf", make_pdf({"/CreationDate": "yesterday-ish"}))
    assert meta is not None and meta.created is None


def test_docx_metadata() -> None:
    meta = extract_metadata("https://example.com/policy.docx", make_docx())
    assert meta is not None
    assert meta.filetype == "docx"
    assert (meta.title, meta.author, meta.last_modified_by) == ("Security Policy", "Jane Smith",
                                                               "jsmith")
    assert meta.software == "Microsoft Office Word 16.0000"
    assert meta.company == "Example Corp"
    assert meta.created == datetime(2025, 3, 4, 9, 15, tzinfo=timezone.utc)


def test_type_comes_from_magic_bytes_not_url() -> None:
    # A PDF served with a .docx name is still a PDF; HTML named .pdf is rejected.
    assert sniff("https://x/file.docx", make_pdf()) == "pdf"
    assert sniff("https://x/file.pdf", b"<html>Not found</html>") is None
    assert sniff("https://x/file.zip", make_docx()) == "ooxml"
    assert extract_metadata("https://x/file.pdf", b"<html>") is None


def test_corrupt_files_return_none() -> None:
    assert extract_metadata("https://x/a.pdf", b"%PDF-1.7 garbage") is None
    assert extract_metadata("https://x/a.docx", b"PK\x03\x04 not really a zip") is None


def test_docx_without_docprops() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/document.xml", "<w:document/>")
    meta = extract_metadata("https://x/a.docx", buffer.getvalue())
    assert meta is not None and meta.author == "" and meta.created is None


def test_oversized_xml_member_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(metadata, "MAX_XML_MEMBER", 100)  # core.xml is bigger than that
    meta = extract_metadata("https://x/a.docx", make_docx())
    assert meta is not None and meta.author == ""  # not read, but no crash


def test_xml_external_entities_not_resolved() -> None:
    evil = (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
        'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        "<dc:creator>&e;</dc:creator></cp:coreProperties>"
    )
    # ElementTree refuses the external entity -> the document is reported unreadable.
    assert extract_metadata("https://x/a.docx", make_docx(core_xml=evil)) is None


def test_invalid_iso_date() -> None:
    meta = extract_metadata(
        "https://x/a.docx",
        make_docx(core_xml=(
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
            'metadata/core-properties" xmlns:dcterms="http://purl.org/dc/terms/">'
            "<dcterms:created>not-a-date</dcterms:created></cp:coreProperties>"
        )),
    )
    assert meta is not None and meta.created is None
