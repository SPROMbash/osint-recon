"""Mask personal data in a report (``--redact-people``), e.g. before sharing it.

* emails -> first character of the local part + ``***``: ``j***@example.com``
  (the domain stays: it describes the organisation, not the person);
* person names -> initials: ``Jane Smith`` -> ``J. S.``;
* applied to emails, people, document authors / last modifiers and the accounts
  listed in breaches. Positions are kept (they describe the organisation).

Returns a new report; the original is untouched.
"""

from __future__ import annotations

from dataclasses import replace

from osint_recon.models import Findings, Report


def mask_email(address: str) -> str:
    local, sep, domain = address.partition("@")
    if not sep:
        return initials(address)
    return f"{local[:1]}***@{domain}" if local else f"***@{domain}"


def initials(name: str) -> str:
    parts = [p for p in name.replace(".", " ").split() if p]
    return " ".join(f"{p[0].upper()}." for p in parts) if parts else ""


def redact_report(report: Report) -> Report:
    f = report.findings
    findings = Findings(
        subdomains=list(f.subdomains),
        emails=[replace(e, address=mask_email(e.address), name=initials(e.name))
                for e in f.emails],
        people=[replace(p, name=initials(p.name)) for p in f.people],
        technologies=list(f.technologies),
        documents=[
            replace(d, author=initials(d.author), last_modified_by=initials(d.last_modified_by))
            for d in f.documents
        ],
        breaches=[replace(b, affected=tuple(mask_email(a) for a in b.affected))
                  for b in f.breaches],
    )
    return replace(report, findings=findings, redacted=True)
