"""JSON report: stable, machine-readable, versioned with a ``schema`` field."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from typing import Any

from osint_recon.models import Report

SCHEMA = "osint-recon/report@1"


def report_to_dict(report: Report) -> dict[str, Any]:
    findings = asdict(report.findings)
    findings.pop("document_links", None)  # internal hand-over between stages
    return {
        "schema": SCHEMA,
        "tool": {"name": "osint-recon", "version": report.tool_version},
        "target": report.target,
        "kind": report.kind,
        "generated": report.generated.isoformat(),
        "active_collection": report.active,
        "partial": report.partial,
        "redacted": report.redacted,
        "summary": {key: len(value) for key, value in findings.items()},
        "sources": [asdict(s) for s in report.sources],
        "findings": findings,
    }


def render_json(report: Report) -> str:
    return json.dumps(report_to_dict(report), indent=2, ensure_ascii=False, default=_default) + "\n"


def _default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"not JSON serialisable: {type(value).__name__}")
