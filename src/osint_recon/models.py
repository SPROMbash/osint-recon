"""Data model shared by sources, runner and reports.

Every finding records **which sources** reported it: a subdomain seen by three
independent sources is more trustworthy than one seen by one, and it lets the
reader verify each claim. Models are frozen; merging builds new instances.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Literal

SourceStatus = Literal["ok", "skipped", "error"]
BreachKind = Literal["service", "domain-accounts", "owned-account"]


def _union(a: tuple[str, ...], b: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(a) | set(b)))


@dataclass(frozen=True)
class Subdomain:
    name: str
    sources: tuple[str, ...]
    addresses: tuple[str, ...] = ()  # filled by DNS resolution / passive DNS


@dataclass(frozen=True)
class Email:
    address: str
    sources: tuple[str, ...]
    name: str = ""
    position: str = ""


@dataclass(frozen=True)
class Person:
    """A name publicly associated with the organisation (no enrichment, no profiling)."""

    name: str
    sources: tuple[str, ...]
    position: str = ""


@dataclass(frozen=True)
class Technology:
    name: str
    category: str
    sources: tuple[str, ...]
    version: str = ""
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class DocumentMeta:
    url: str
    filetype: str
    size: int
    title: str = ""
    author: str = ""
    last_modified_by: str = ""
    software: str = ""  # Creator/Producer (PDF) or Application (Office)
    company: str = ""
    created: datetime | None = None
    modified: datetime | None = None


@dataclass(frozen=True)
class Breach:
    name: str
    kind: BreachKind
    title: str = ""
    breach_date: str = ""
    pwn_count: int = 0
    data_classes: tuple[str, ...] = ()
    affected: tuple[str, ...] = ()  # aliases / owned emails (personal data: redactable)


@dataclass(frozen=True)
class SourceResult:
    source: str
    status: SourceStatus
    message: str = ""
    duration: float = 0.0
    findings: int = 0


@dataclass
class Findings:
    """What one source (or a merge of several) found. Mutable while collecting."""

    subdomains: list[Subdomain] = field(default_factory=list)
    emails: list[Email] = field(default_factory=list)
    people: list[Person] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    documents: list[DocumentMeta] = field(default_factory=list)
    breaches: list[Breach] = field(default_factory=list)
    # Internal hand-over between stages (not reported): document URLs found by the crawler.
    document_links: list[str] = field(default_factory=list)

    def count(self) -> int:
        return (
            len(self.subdomains) + len(self.emails) + len(self.people)
            + len(self.technologies) + len(self.documents) + len(self.breaches)
        )


@dataclass(frozen=True)
class Report:
    target: str
    kind: Literal["domain", "footprint"]
    generated: datetime
    tool_version: str
    active: bool
    sources: tuple[SourceResult, ...]
    findings: Findings
    partial: bool = False
    redacted: bool = False


def merge(parts: list[Findings]) -> Findings:
    """Merge and de-duplicate findings from several sources."""
    subs: dict[str, Subdomain] = {}
    emails: dict[str, Email] = {}
    people: dict[str, Person] = {}
    techs: dict[str, Technology] = {}
    docs: dict[str, DocumentMeta] = {}
    breaches: dict[tuple[str, str], Breach] = {}
    links: dict[str, None] = {}

    for part in parts:
        for s in part.subdomains:
            old = subs.get(s.name)
            subs[s.name] = s if old is None else replace(
                old,
                sources=_union(old.sources, s.sources),
                addresses=_union(old.addresses, s.addresses),
            )
        for e in part.emails:
            key = e.address.lower()
            old_e = emails.get(key)
            emails[key] = replace(e, address=key) if old_e is None else replace(
                old_e,
                sources=_union(old_e.sources, e.sources),
                name=old_e.name or e.name,
                position=old_e.position or e.position,
            )
        for p in part.people:
            key = " ".join(p.name.lower().split())
            old_p = people.get(key)
            people[key] = p if old_p is None else replace(
                old_p,
                sources=_union(old_p.sources, p.sources),
                position=old_p.position or p.position,
            )
        for t in part.technologies:
            key = t.name.lower()
            old_t = techs.get(key)
            techs[key] = t if old_t is None else replace(
                old_t,
                sources=_union(old_t.sources, t.sources),
                version=old_t.version or t.version,
                evidence=tuple(dict.fromkeys((*old_t.evidence, *t.evidence))),
            )
        for d in part.documents:
            docs.setdefault(d.url, d)
        for b in part.breaches:
            key_b = (b.kind, b.name)
            old_b = breaches.get(key_b)
            breaches[key_b] = b if old_b is None else replace(
                old_b, affected=_union(old_b.affected, b.affected)
            )
        links.update(dict.fromkeys(part.document_links))

    return Findings(
        subdomains=sorted(subs.values(), key=lambda s: s.name),
        emails=sorted(emails.values(), key=lambda e: e.address),
        people=sorted(people.values(), key=lambda p: p.name.lower()),
        technologies=sorted(techs.values(), key=lambda t: (t.category, t.name)),
        documents=sorted(docs.values(), key=lambda d: d.url),
        breaches=sorted(breaches.values(), key=lambda b: (b.kind, b.name)),
        document_links=list(links),
    )
