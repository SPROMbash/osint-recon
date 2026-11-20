"""Build small real documents in memory for tests (no binary fixtures in the repo)."""

from __future__ import annotations

import io
import zipfile

from pypdf import PdfWriter


def make_pdf(metadata: dict[str, str] | None = None, *, user_password: str | None = None) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    if metadata:
        writer.add_metadata(metadata)
    if user_password is not None:
        writer.encrypt(user_password=user_password, owner_password="owner-secret")
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


CORE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
  xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>{title}</dc:title>
  <dc:creator>{creator}</dc:creator>
  <cp:lastModifiedBy>{modified_by}</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">2025-03-04T09:15:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2026-01-20T17:42:00Z</dcterms:modified>
</cp:coreProperties>"""

APP_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <AppVersion>16.0000</AppVersion>
  <Company>{company}</Company>
</Properties>"""


def make_docx(
    *,
    title: str = "Security Policy",
    creator: str = "Jane Smith",
    modified_by: str = "jsmith",
    company: str = "Example Corp",
    core_xml: str | None = None,
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<w:document/>")
        archive.writestr(
            "docProps/core.xml",
            core_xml or CORE_XML.format(title=title, creator=creator, modified_by=modified_by),
        )
        archive.writestr("docProps/app.xml", APP_XML.format(company=company))
    return buffer.getvalue()
