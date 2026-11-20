"""Human-readable Markdown report."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from osint_recon.models import Breach, Report

_STATUS = {"ok": "ok", "skipped": "skipped", "error": "**error**"}
_KIND_TITLE = {
    "service": "Breaches of the service at this domain",
    "domain-accounts": "Accounts of the domain found in breaches (verified domain)",
    "owned-account": "Your own addresses found in breaches",
}


def render_markdown(report: Report) -> str:
    f = report.findings
    out: list[str] = []
    title = "Digital footprint" if report.kind == "footprint" else f"OSINT report: {report.target}"
    out += [f"# {title}", ""]
    collection = "passive + active (authorised scope)" if report.active else "passive only"
    out += [
        f"- **Generated:** {report.generated.isoformat(sep=' ')}",
        f"- **Tool:** osint-recon {report.tool_version}",
        f"- **Collection:** {collection}",
    ]
    if report.redacted:
        out.append("- **Personal data:** redacted (`--redact-people`)")
    out.append("")
    if report.partial:
        out += ["> **Warning:** PARTIAL REPORT: the run was interrupted (Ctrl+C). "
                "Sources marked as interrupted did not finish.", ""]
    out += [
        "> Compiled from **public** sources for authorised security assessment or to "
        "review your own exposure. It contains personal data: store it securely, share it "
        "only with those who need it and delete it when no longer needed.",
        "",
    ]

    out += ["## Summary", "", "| Finding | Count |", "|---|---|"]
    for label, items in (
        ("Subdomains", f.subdomains), ("Emails", f.emails), ("People", f.people),
        ("Technologies", f.technologies), ("Documents", f.documents), ("Breaches", f.breaches),
    ):
        out.append(f"| {label} | {len(items)} |")
    out.append("")

    out += ["## Sources", "", "| Source | Status | Findings | Time | Notes |",
            "|---|---|---|---|---|"]
    for s in report.sources:
        out.append(
            f"| {s.source} | {_STATUS[s.status]} | {s.findings} | "
            f"{s.duration:.1f}s | {_cell(s.message) or '-'} |"
        )
    out.append("")

    if report.kind == "domain":
        out += _section(
            "Subdomains",
            ["Host", "Addresses", "Sources"],
            ([s.name, ", ".join(s.addresses), ", ".join(s.sources)] for s in f.subdomains),
            len(f.subdomains),
        )
        out += _section(
            "Emails",
            ["Address", "Name", "Position", "Sources"],
            ([e.address, e.name, e.position, ", ".join(e.sources)] for e in f.emails),
            len(f.emails),
        )
        out += _section(
            "People",
            ["Name", "Position", "Sources"],
            ([p.name, p.position, ", ".join(p.sources)] for p in f.people),
            len(f.people),
        )
        out += _section(
            "Technologies",
            ["Technology", "Version", "Category", "Evidence"],
            ([t.name, t.version, t.category, "; ".join(t.evidence[:3])] for t in f.technologies),
            len(f.technologies),
        )
        out += _section(
            "Documents",
            ["Document", "Type", "Author", "Last modified by", "Software", "Created"],
            (
                [d.url, d.filetype, d.author, d.last_modified_by, d.software,
                 d.created.date().isoformat() if d.created else ""]
                for d in f.documents
            ),
            len(f.documents),
        )
    out += _breaches(f.breaches)
    return "\n".join(out).rstrip() + "\n"


def _breaches(breaches: Sequence[Breach]) -> list[str]:
    out = ["## Breaches", ""]
    if not breaches:
        return [*out, "_None found._", ""]
    for kind, title in _KIND_TITLE.items():
        group = [b for b in breaches if b.kind == kind]
        if not group:
            continue
        out += [f"### {title}", "", "| Breach | Date | Accounts (total) | Data | Affected |",
                "|---|---|---|---|---|"]
        for b in group:
            affected = ", ".join(b.affected[:10]) + (" ..." if len(b.affected) > 10 else "")
            out.append(
                f"| {_cell(b.title or b.name)} | {b.breach_date} | {b.pwn_count:,} | "
                f"{_cell(', '.join(b.data_classes))} | {_cell(affected) or '-'} |"
            )
        out.append("")
    return out


def _section(
    title: str, headers: list[str], rows: Iterable[list[str]], count: int
) -> list[str]:
    out = [f"## {title}", ""]
    if not count:
        return [*out, "_None found._", ""]
    out += ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_cell(c) or "-" for c in row) + " |" for row in rows]
    return [*out, ""]


def _cell(text: str) -> str:
    """Escape what would break a Markdown table cell."""
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()
