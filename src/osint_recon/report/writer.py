"""Write report files atomically: ``<output_dir>/<target>-<timestamp>.{md,json}``."""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterable
from pathlib import Path

from osint_recon.models import Report
from osint_recon.report.json_report import render_json
from osint_recon.report.markdown import render_markdown

FORMATS = ("md", "json")


def report_basename(report: Report) -> str:
    safe = re.sub(r"[^a-z0-9.-]+", "-", report.target.lower()).strip("-") or report.kind
    return f"{safe}-{report.generated.strftime('%Y%m%d-%H%M%S')}"


def write_reports(report: Report, output_dir: Path, formats: Iterable[str]) -> list[Path]:
    renderers = {"md": render_markdown, "json": render_json}
    base = report_basename(report)
    written: list[Path] = []
    for fmt in formats:
        path = output_dir / f"{base}.{fmt}"
        atomic_write(path, renderers[fmt](report))
        written.append(path)
    return written


def atomic_write(path: Path, text: str) -> None:
    """Temp file in the same folder + ``os.replace``: never a half-written report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
