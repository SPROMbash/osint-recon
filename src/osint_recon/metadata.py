"""Extract metadata from public documents (pure functions: bytes in, DocumentMeta out).

Supported formats:

* **PDF**: the Info dictionary via ``pypdf`` (Title, Author, Creator, Producer, dates).
* **Office Open XML** (.docx / .xlsx / .pptx): these are ZIP files; ``docProps/core.xml``
  holds title, creator, lastModifiedBy and dates, ``docProps/app.xml`` the
  application, its version and the company. Read with the standard library.

Documents come from third parties, so they are treated as untrusted:

* the type is decided by the file's magic bytes, not by the URL;
* from a ZIP only those two small members are read, after checking their declared
  size and reading at most that limit (zip-bomb safe);
* XML is parsed with ElementTree, which does not resolve external entities;
* any parsing failure returns ``None`` (corrupt file) instead of raising.
"""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlsplit

from pypdf import PasswordType, PdfReader

from osint_recon.log import get_logger
from osint_recon.models import DocumentMeta

log = get_logger(__name__)

MAX_XML_MEMBER = 1_000_000  # docProps files are a few KB; anything bigger is suspicious

_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}
_OOXML_TYPES = {".docx": "docx", ".xlsx": "xlsx", ".pptx": "pptx"}


def sniff(url: str, data: bytes) -> str | None:
    """Real file type from magic bytes (the URL extension only refines Office types)."""
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        suffix = "." + urlsplit(url).path.rsplit(".", 1)[-1].lower()
        return _OOXML_TYPES.get(suffix, "ooxml")
    return None


def extract_metadata(url: str, data: bytes) -> DocumentMeta | None:
    kind = sniff(url, data)
    if kind is None:
        return None
    try:
        if kind == "pdf":
            return _pdf(url, data)
        return _ooxml(url, data, kind)
    except Exception as exc:  # untrusted input: never let a broken file crash the run
        log.debug("Could not parse %s (%s): %s", url, kind, exc)
        return None


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #
def _pdf(url: str, data: bytes) -> DocumentMeta:
    reader = PdfReader(io.BytesIO(data))
    # Many "protected" PDFs only restrict printing/editing and open with an empty
    # user password. decrypt() does not raise on a wrong password: it returns
    # NOT_DECRYPTED, and reading the metadata afterwards would fail.
    if reader.is_encrypted and reader.decrypt("") == PasswordType.NOT_DECRYPTED:
        return DocumentMeta(url=url, filetype="pdf", size=len(data))
    info = reader.metadata
    if info is None:
        return DocumentMeta(url=url, filetype="pdf", size=len(data))

    software = " / ".join(dict.fromkeys(s for s in (_s(info.creator), _s(info.producer)) if s))
    return DocumentMeta(
        url=url,
        filetype="pdf",
        size=len(data),
        title=_s(info.title),
        author=_s(info.author),
        software=software,
        created=_safe_date(lambda: info.creation_date),
        modified=_safe_date(lambda: info.modification_date),
    )


def _safe_date(getter: Callable[[], object]) -> datetime | None:
    """pypdf raises on malformed date strings; treat them as missing."""
    try:
        value = getter()
    except Exception:
        return None
    return value if isinstance(value, datetime) else None


# --------------------------------------------------------------------------- #
# Office Open XML
# --------------------------------------------------------------------------- #
def _ooxml(url: str, data: bytes, kind: str) -> DocumentMeta:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        core = _xml_member(archive, "docProps/core.xml")
        app = _xml_member(archive, "docProps/app.xml")

    def core_text(tag: str) -> str:
        return _text(core, tag)

    application = _text(app, "ep:Application")
    version = _text(app, "ep:AppVersion")
    return DocumentMeta(
        url=url,
        filetype=kind,
        size=len(data),
        title=core_text("dc:title"),
        author=core_text("dc:creator"),
        last_modified_by=core_text("cp:lastModifiedBy"),
        software=f"{application} {version}".strip(),
        company=_text(app, "ep:Company"),
        created=_iso_date(core_text("dcterms:created")),
        modified=_iso_date(core_text("dcterms:modified")),
    )


def _xml_member(archive: zipfile.ZipFile, name: str) -> ET.Element | None:
    try:
        info = archive.getinfo(name)
    except KeyError:
        return None
    if info.file_size > MAX_XML_MEMBER:
        log.debug("Skipping oversized %s (%d bytes declared)", name, info.file_size)
        return None
    with archive.open(info) as handle:
        raw = handle.read(MAX_XML_MEMBER + 1)
    if len(raw) > MAX_XML_MEMBER:  # declared size lied
        return None
    return ET.fromstring(raw)


def _text(root: ET.Element | None, tag: str) -> str:
    if root is None:
        return ""
    node = root.find(tag, _NS)
    return (node.text or "").strip() if node is not None else ""


def _iso_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))  # 3.10: no "Z"
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _s(value: object) -> str:
    return str(value).strip() if value else ""
