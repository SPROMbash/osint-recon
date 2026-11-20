"""Polite crawl of the target website (ACTIVE): technologies, emails, document links.

Rules of politeness, enforced in code:

* ``robots.txt`` is read first. Missing (4xx) -> everything allowed. Server error
  (5xx) or unreachable -> nothing is crawled (RFC 9309's conservative reading).
* Only the start host is crawled, up to ``crawl.max_pages`` pages and
  ``crawl.max_depth`` link levels; redirects that leave the domain are ignored.
* Requests go through the source's rate limiter and carry an honest User-Agent.
* Document links are only kept if robots.txt allows them, so the documents
  source inherits the same restrictions.

HTML is parsed with the standard library ``html.parser`` (no extra dependency,
tolerant of broken markup).
"""

from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import unquote, urldefrag, urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from osint_recon.errors import SourceError
from osint_recon.log import get_logger
from osint_recon.models import Email, Findings, Subdomain, Technology
from osint_recon.scope import belongs_to, clean_hostname, email_belongs_to
from osint_recon.sources.base import Source, SourceContext
from osint_recon.sources.techdetect import PageSignals, detect

log = get_logger(__name__)

DOCUMENT_EXTENSIONS = (".pdf", ".docx", ".xlsx", ".pptx")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")


class _PageParser(HTMLParser):
    """Collects links, script sources, generator metas and mailto addresses."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.generators: list[str] = []
        self.mailtos: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area") and values.get("href"):
            href = values["href"].strip()
            if href.lower().startswith("mailto:"):
                self.mailtos.append(unquote(href[7:].split("?", 1)[0]))
            else:
                self.links.append(href)
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        elif tag == "meta" and values.get("name", "").lower() == "generator":
            self.generators.append(values.get("content", ""))


class WebsiteSource(Source):
    name = "website"
    description = "Polite crawl of the website: technologies, emails, documents (active)"
    active = True
    stage = 1

    async def collect(self, ctx: SourceContext) -> Findings:
        origin, robots = await self._find_origin(ctx)
        start_host = urlsplit(origin).hostname or ctx.domain
        agent = ctx.config.http.user_agent
        max_pages, max_depth = ctx.config.crawl.max_pages, ctx.config.crawl.max_depth

        queue: deque[tuple[str, int]] = deque([(origin + "/", 0)])
        seen: set[str] = {origin + "/"}
        techs: list[Technology] = []
        emails: dict[str, None] = {}
        docs: dict[str, None] = {}
        hosts: dict[str, None] = {}
        pages = blocked = failed = 0

        while queue and pages < max_pages:
            url, depth = queue.popleft()
            if not robots.can_fetch(agent, url):
                blocked += 1
                continue
            try:
                response = await ctx.http.get(url)
            except SourceError as exc:
                failed += 1
                log.debug("[website] %s", exc)
                continue
            final = str(response.url)
            if response.status_code >= 400 or not _is_html(response):
                continue
            if not belongs_to(urlsplit(final).hostname or "", ctx.domain):
                continue  # redirected off-site
            pages += 1

            parser = _PageParser()
            parser.feed(response.text)
            signals = PageSignals(
                url=final,
                headers={k.lower(): v for k, v in response.headers.items()},
                cookies=list(response.cookies.keys()),
                generators=parser.generators,
                scripts=[urljoin(final, s) for s in parser.scripts],
                html=response.text,
            )
            techs.extend(detect(signals))

            for address in [*parser.mailtos, *_EMAIL_RE.findall(response.text)]:
                if email_belongs_to(address, ctx.domain):
                    emails[address.lower()] = None

            for href in parser.links:
                link = _normalise(final, href)
                if link is None:
                    continue
                host = urlsplit(link).hostname or ""
                if not belongs_to(host, ctx.domain):
                    continue
                if clean := clean_hostname(host):
                    hosts[clean] = None
                if urlsplit(link).path.lower().endswith(DOCUMENT_EXTENSIONS):
                    if robots.can_fetch(agent, link):
                        docs[link] = None
                elif host == start_host and depth < max_depth and link not in seen:
                    seen.add(link)
                    queue.append((link, depth + 1))

        ctx.notes.append(
            f"{pages} page(s) crawled from {origin}"
            + (f", {blocked} blocked by robots.txt" if blocked else "")
            + (f", {failed} failed" if failed else "")
            + (f", stopped at crawl.max_pages={max_pages}" if queue and pages >= max_pages else "")
        )
        return Findings(
            technologies=techs,
            emails=[Email(a, (self.name,)) for a in emails],
            subdomains=[Subdomain(h, (self.name,)) for h in hosts],
            document_links=list(docs),
        )

    async def _find_origin(self, ctx: SourceContext) -> tuple[str, RobotFileParser]:
        """First reachable origin among https://domain, https://www.domain, http://domain."""
        candidates = [f"https://{ctx.domain}", f"https://www.{ctx.domain}", f"http://{ctx.domain}"]
        for origin in candidates:
            try:
                response = await ctx.http.get(origin + "/robots.txt")
            except SourceError as exc:
                if exc.status is not None and exc.status >= 500:
                    # The server IS there but failing: do not try other origins.
                    raise _robots_server_error(origin, exc.status) from None
                continue  # network failure: try the next candidate
            robots = RobotFileParser()
            if response.status_code >= 500:
                raise _robots_server_error(origin, response.status_code)
            if 400 <= response.status_code < 500:
                robots.parse([])  # no robots.txt: everything allowed
            else:
                robots.parse(response.text.splitlines())
            return origin, robots
        raise SourceError(f"website: not reachable ({', '.join(candidates)})")


def _robots_server_error(origin: str, status: int) -> SourceError:
    return SourceError(
        f"website: robots.txt at {origin} returned HTTP {status}; "
        "not crawling (RFC 9309: treat as disallow all)",
        status=status,
    )


def _is_html(response: httpx.Response) -> bool:
    return "html" in response.headers.get("Content-Type", "").lower()


def _normalise(base: str, href: str) -> str | None:
    """Absolute http(s) URL without fragment, or None (javascript:, tel:, data:...)."""
    url, _ = urldefrag(urljoin(base, href))
    return url if urlsplit(url).scheme in ("http", "https") else None
