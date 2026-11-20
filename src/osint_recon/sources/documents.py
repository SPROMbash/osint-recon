"""Metadata of public documents linked from the target website (ACTIVE, stage 2).

Downloads the document links found by the crawler (which already filtered them
through robots.txt), with a size cap, and extracts their metadata. Author and
"last modified by" names become :class:`Person` findings, except generic
placeholders ("Administrator", "Microsoft Office User"...), and the producing
software becomes a :class:`Technology` (internal software versions are a
classic OSINT finding).
"""

from __future__ import annotations

import asyncio

from osint_recon.errors import SourceError
from osint_recon.metadata import extract_metadata
from osint_recon.models import DocumentMeta, Findings, Person, Technology
from osint_recon.sources.base import Source, SourceContext

GENERIC_NAMES = frozenset(
    {
        "admin", "administrator", "administrador", "user", "usuario", "owner",
        "author", "unknown", "microsoft office user", "windows user", "default",
    }
)


class DocumentsSource(Source):
    name = "documents"
    description = "Metadata of public documents linked from the website (active)"
    active = True
    stage = 2

    async def collect(self, ctx: SourceContext) -> Findings:
        links = ctx.previous.document_links
        limit = ctx.config.crawl.max_documents
        if not links:
            ctx.notes.append("no public documents were found by the crawler")
            return Findings()
        if len(links) > limit:
            ctx.notes.append(f"analysed the first {limit} of {len(links)} documents")
            links = links[:limit]

        max_bytes = int(ctx.config.crawl.max_document_mb * 1024 * 1024)

        async def fetch(url: str) -> tuple[str, bytes | None, str]:
            try:
                return url, await ctx.http.get_bytes(url, max_bytes=max_bytes), ""
            except SourceError as exc:
                return url, None, str(exc)

        results = await asyncio.gather(*(fetch(u) for u in links))

        documents: list[DocumentMeta] = []
        too_big = failed = unreadable = 0
        for url, data, error in results:
            if error:
                failed += 1
            elif data is None:
                too_big += 1
            elif (meta := extract_metadata(url, data)) is None:
                unreadable += 1
            else:
                documents.append(meta)

        problems = [
            f"{n} {label}"
            for n, label in (
                (too_big, f"over {ctx.config.crawl.max_document_mb:g} MB"),
                (failed, "failed to download"),
                (unreadable, "unsupported or corrupt"),
            )
            if n
        ]
        ctx.notes.append(
            f"{len(documents)} of {len(links)} document(s) analysed"
            + (f" ({', '.join(problems)})" if problems else "")
        )

        people: dict[str, Person] = {}
        techs: dict[str, Technology] = {}
        for doc in documents:
            for name in (doc.author, doc.last_modified_by):
                if name and name.strip().lower() not in GENERIC_NAMES:
                    people.setdefault(name.lower(), Person(name, (self.name,)))
            if doc.software:
                techs.setdefault(
                    doc.software.lower(),
                    Technology(
                        doc.software, "Document software", (self.name,),
                        evidence=(f"document {doc.url}",),
                    ),
                )

        return Findings(
            documents=documents, people=list(people.values()), technologies=list(techs.values())
        )
