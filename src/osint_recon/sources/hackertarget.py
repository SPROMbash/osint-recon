"""Subdomains (+ IPs) from HackerTarget's hostsearch API (passive, no key).

The free tier allows 50 queries per day. The API answers in plain text
(``host,ip`` per line) and reports errors *with HTTP 200* as text such as
"API count exceeded", so the body has to be inspected.
"""

from __future__ import annotations

from osint_recon.errors import SourceError
from osint_recon.http import check_status
from osint_recon.models import Findings, Subdomain
from osint_recon.scope import belongs_to, clean_hostname, is_ip
from osint_recon.sources.base import Source, SourceContext

URL = "https://api.hackertarget.com/hostsearch/"


class HackerTargetSource(Source):
    name = "hackertarget"
    description = "HackerTarget hostsearch (free: 50 queries/day)"

    async def collect(self, ctx: SourceContext) -> Findings:
        response = await ctx.http.get(URL, params={"q": ctx.domain})
        check_status(response, self.name)
        text = response.text.strip()
        lowered = text.lower()

        if not text or lowered.startswith("no records"):
            return Findings()
        if "api count exceeded" in lowered:
            raise SourceError("hackertarget: free daily quota exceeded (50 queries/day)")
        if lowered.startswith("error"):
            raise SourceError(f"hackertarget: {text.splitlines()[0][:120]}")

        found: dict[str, set[str]] = {}
        for line in text.splitlines():
            raw_host, _, raw_ip = line.partition(",")
            host = clean_hostname(raw_host)
            if not host or not belongs_to(host, ctx.domain):
                continue
            addresses = found.setdefault(host, set())
            if is_ip(raw_ip.strip()):
                addresses.add(raw_ip.strip())

        return Findings(
            subdomains=[
                Subdomain(host, (self.name,), tuple(sorted(ips)))
                for host, ips in sorted(found.items())
            ]
        )

