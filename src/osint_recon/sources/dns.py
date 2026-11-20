"""Resolve discovered subdomains (ACTIVE, stage 2).

Passive sources report names that existed at some point; resolving them shows
which ones are alive *now*. It queries DNS servers about the target, so it is
treated as active and only runs within the authorised scope.

Wildcard DNS: if ``*.example.com`` resolves, every made-up name "exists". A
random label is resolved first; hosts that only resolve to the wildcard's IPs
are dropped and the report says so.

The resolver is injectable (``resolve=``) so tests never touch real DNS.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable

import dns.asyncresolver
import dns.exception
import dns.resolver

from osint_recon.models import Findings, Subdomain
from osint_recon.sources.base import Source, SourceContext

Resolve = Callable[[str], Awaitable[tuple[str, ...]]]

_NOT_FOUND = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.exception.Timeout,
)


class SystemResolver:
    """A/AAAA lookup with dnspython's asyncio resolver (system nameservers)."""

    def __init__(self, lifetime: float = 5.0) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        self._lifetime = lifetime

    async def __call__(self, name: str) -> tuple[str, ...]:
        addresses: set[str] = set()
        for rtype in ("A", "AAAA"):
            try:
                answer = await self._resolver.resolve(name, rtype, lifetime=self._lifetime)
            except _NOT_FOUND:
                continue
            addresses.update(record.to_text() for record in answer)
        return tuple(sorted(addresses))


class DnsSource(Source):
    name = "dns"
    description = "DNS resolution of discovered subdomains (active)"
    active = True
    stage = 2

    def __init__(self, resolve: Resolve | None = None) -> None:
        self._resolve = resolve

    async def collect(self, ctx: SourceContext) -> Findings:
        resolve = self._resolve or SystemResolver()
        hosts = list(dict.fromkeys([ctx.domain, *(s.name for s in ctx.previous.subdomains)]))
        limit = ctx.config.dns_max_hosts
        if len(hosts) > limit:
            ctx.notes.append(
                f"resolved only the first {limit} of {len(hosts)} hosts (dns.max_hosts)"
            )
            hosts = hosts[:limit]

        wildcard = await resolve(f"osint-recon-{secrets.token_hex(6)}.{ctx.domain}")
        if wildcard:
            ctx.notes.append(
                f"wildcard DNS detected (*.{ctx.domain} -> {', '.join(wildcard)}); "
                "hosts resolving only to those IPs were discarded"
            )

        async def lookup(host: str) -> tuple[str, tuple[str, ...]]:
            async with ctx.limiter:
                return host, await resolve(host)

        results = await asyncio.gather(*(lookup(h) for h in hosts))

        alive: list[Subdomain] = []
        for host, addresses in results:
            if not addresses:
                continue
            if wildcard and host != ctx.domain and set(addresses) <= set(wildcard):
                continue
            alive.append(Subdomain(host, (self.name,), addresses))
        ctx.notes.append(f"{len(alive)} of {len(hosts)} hosts resolve")
        return Findings(subdomains=alive)
