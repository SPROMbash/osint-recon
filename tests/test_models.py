"""Tests for merging / de-duplicating findings from several sources."""

from __future__ import annotations

from osint_recon.models import (
    Breach,
    DocumentMeta,
    Email,
    Findings,
    Person,
    Subdomain,
    Technology,
    merge,
)


def test_merge_deduplicates_and_unions_sources() -> None:
    a = Findings(
        subdomains=[Subdomain("www.example.com", ("crtsh",))],
        emails=[Email("John@Example.com", ("hunter",), name="John Doe")],
        people=[Person("John  Doe", ("hunter",), position="CTO")],
        technologies=[Technology("nginx", "Web server", ("website",), evidence=("Server",))],
        documents=[DocumentMeta("https://example.com/a.pdf", "pdf", 10)],
        breaches=[Breach("Adobe", "domain-accounts", affected=("john",))],
        document_links=["https://example.com/a.pdf"],
    )
    b = Findings(
        subdomains=[
            Subdomain("www.example.com", ("dns",), addresses=("93.184.216.34",)),
            Subdomain("api.example.com", ("otx",)),
        ],
        emails=[Email("john@example.com", ("website",), position="CTO")],
        people=[Person("john doe", ("documents",))],
        technologies=[Technology("nginx", "Web server", ("website",), version="1.25")],
        documents=[DocumentMeta("https://example.com/a.pdf", "pdf", 10)],
        breaches=[Breach("Adobe", "domain-accounts", affected=("jane",))],
        document_links=["https://example.com/a.pdf", "https://example.com/b.docx"],
    )

    m = merge([a, b])

    assert [s.name for s in m.subdomains] == ["api.example.com", "www.example.com"]
    www = m.subdomains[1]
    assert www.sources == ("crtsh", "dns") and www.addresses == ("93.184.216.34",)

    (email,) = m.emails
    assert email.address == "john@example.com"
    assert email.sources == ("hunter", "website")
    assert (email.name, email.position) == ("John Doe", "CTO")

    (person,) = m.people  # "John  Doe" == "john doe"
    assert person.sources == ("documents", "hunter") and person.position == "CTO"

    (tech,) = m.technologies
    assert tech.version == "1.25" and tech.evidence == ("Server",)
    assert len(m.documents) == 1
    assert m.breaches[0].affected == ("jane", "john")
    assert m.document_links == ["https://example.com/a.pdf", "https://example.com/b.docx"]
    assert m.count() == 2 + 1 + 1 + 1 + 1 + 1


def test_merge_empty() -> None:
    assert merge([]).count() == 0
