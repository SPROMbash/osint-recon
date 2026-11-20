"""Subdomains from AlienVault OTX passive DNS (passive; API key optional).

Passive DNS databases record which hostnames have resolved to which IPs over
time, as observed by sensors around the world. OTX works without a key with a
lower rate limit; with ``OSINT_RECON_OTX_KEY`` the key is sent in the header.
"""

from __future__ import annotations

from osint_recon.errors import SourceError
from osint_recon.models import Findings, Subdomain
from osint_recon.scope import belongs_to, clean_hostname, is_ip
from osint_recon.sources.base import Source, SourceContext

URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"


class OtxSource(Source):
    name = "otx"
    description = "AlienVault OTX passive DNS (key optional)"

    async def collect(self, ctx: SourceContext) -> Findings:
        key = ctx.config.key("otx")
        headers = {"X-OTX-API-KEY": key} if key else None
        data = await ctx.http.get_json(URL.format(domain=ctx.domain), headers=headers)
        records = data.get("passive_dns") if isinstance(data, dict) else None
        if not isinstance(records, list):
            raise SourceError("otx: unexpected response format")

        found: dict[str, set[str]] = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            host = clean_hostname(str(record.get("hostname") or ""))
            if not host or not belongs_to(host, ctx.domain):
                continue
            addresses = found.setdefault(host, set())
            address = str(record.get("address") or "")
            if record.get("record_type") in ("A", "AAAA") and is_ip(address):
                addresses.add(address)

        return Findings(
            subdomains=[
                Subdomain(host, (self.name,), tuple(sorted(ips)))
                for host, ips in sorted(found.items())
            ]
        )

