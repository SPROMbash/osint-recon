"""Subdomains from Certificate Transparency logs via crt.sh (passive, no key).

Every publicly trusted TLS certificate is logged in CT logs, so the names in
certificates issued for ``*.example.com`` reveal subdomains without touching the
target. crt.sh returns one JSON object per certificate; ``name_value`` holds the
SAN entries separated by newlines and often includes wildcards (``*.dev...``)
and unrelated domains, which are cleaned and filtered here.
"""

from __future__ import annotations

from osint_recon.errors import SourceError
from osint_recon.models import Findings, Subdomain
from osint_recon.scope import belongs_to, clean_hostname
from osint_recon.sources.base import Source, SourceContext

URL = "https://crt.sh/"


class CrtShSource(Source):
    name = "crtsh"
    description = "Certificate Transparency logs (crt.sh)"

    async def collect(self, ctx: SourceContext) -> Findings:
        data = await ctx.http.get_json(URL, params={"q": f"%.{ctx.domain}", "output": "json"})
        if not isinstance(data, list):
            raise SourceError("crtsh: unexpected response format")

        names: set[str] = set()
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for field_name in ("name_value", "common_name"):
                for raw in str(entry.get(field_name) or "").splitlines():
                    host = clean_hostname(raw)
                    if host and belongs_to(host, ctx.domain):
                        names.add(host)

        return Findings(subdomains=[Subdomain(n, (self.name,)) for n in sorted(names)])
