"""Known data breaches via Have I Been Pwned (API v3). Passive.

Ethics are enforced here, not just documented:

* **Domain scan** (:class:`HibpSource`):
  - always: ``/breaches?domain=`` — breaches *of the service* running on the
    domain (no key needed, no personal data);
  - with an API key: ``/breacheddomain/{domain}`` — accounts on the domain found
    in breaches. HIBP itself only answers this for domains **you have verified**
    in your HIBP dashboard; otherwise it is skipped with an explanation.
  - emails found by other sources are NEVER looked up one by one.
* **Footprint** (:class:`HibpFootprintSource`): checks only the ``owned_emails``
  from your config — your own addresses — with ``/breachedaccount/{email}``.

HIBP requires a User-Agent (sent by the shared client) and enforces per-key
rate limits (Pwned 1 plan: 10 requests/min -> ``min_interval: 6.5`` by default).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from osint_recon.errors import SourceError
from osint_recon.http import check_status
from osint_recon.models import Breach, BreachKind, Findings
from osint_recon.sources.base import Source, SourceContext

API = "https://haveibeenpwned.com/api/v3"


def parse_breach(obj: dict[str, Any], kind: BreachKind, affected: tuple[str, ...] = ()) -> Breach:
    classes = obj.get("DataClasses") or []
    return Breach(
        name=str(obj.get("Name") or "?"),
        kind=kind,
        title=str(obj.get("Title") or obj.get("Name") or ""),
        breach_date=str(obj.get("BreachDate") or ""),
        pwn_count=int(obj.get("PwnCount") or 0),
        data_classes=tuple(str(c) for c in classes if isinstance(c, str)),
        affected=affected,
    )


class HibpSource(Source):
    name = "hibp"
    description = "Have I Been Pwned: breaches of the domain (key optional)"

    async def collect(self, ctx: SourceContext) -> Findings:
        breaches: list[Breach] = []

        service = await ctx.http.get_json(f"{API}/breaches", params={"domain": ctx.domain})
        if not isinstance(service, list):
            raise SourceError("hibp: unexpected response format")
        breaches += [parse_breach(b, "service") for b in service if isinstance(b, dict)]
        ctx.notes.append(f"{len(breaches)} breach(es) of the service at {ctx.domain}")

        key = ctx.config.key("hibp")
        if not key:
            ctx.notes.append(
                "no HIBP API key: accounts of the domain in breaches were not checked"
            )
            return Findings(breaches=breaches)

        headers = {"hibp-api-key": key}
        response = await ctx.http.get(f"{API}/breacheddomain/{ctx.domain}", headers=headers)
        if response.status_code == 404:
            ctx.notes.append("no accounts of the domain appear in known breaches")
            return Findings(breaches=breaches)
        if response.status_code == 403:
            ctx.notes.append(
                f"{ctx.domain} is not verified in your HIBP dashboard: per-account data skipped "
                "(HIBP only discloses it to verified domain owners)"
            )
            return Findings(breaches=breaches)
        check_status(response, self.name)
        aliases_by_breach = _invert(response.json(), ctx.domain)

        catalogue = await ctx.http.get_json(f"{API}/breaches")  # details of every breach
        details = {
            str(b.get("Name")): b for b in (catalogue if isinstance(catalogue, list) else [])
            if isinstance(b, dict)
        }
        for name, accounts in sorted(aliases_by_breach.items()):
            obj = details.get(name, {"Name": name})
            breaches.append(parse_breach(obj, "domain-accounts", tuple(sorted(accounts))))
        ctx.notes.append(
            f"{sum(len(a) for a in aliases_by_breach.values())} account appearance(s) "
            f"in {len(aliases_by_breach)} breach(es)"
        )
        return Findings(breaches=breaches)


class HibpFootprintSource(Source):
    """Your own digital footprint: only ``owned_emails`` are ever looked up."""

    name = "hibp"
    description = "Have I Been Pwned: breaches of YOUR own email addresses (API key)"
    key_name = "hibp"

    async def collect(self, ctx: SourceContext) -> Findings:
        headers = {"hibp-api-key": ctx.config.key("hibp")}
        breaches: list[Breach] = []
        clean = 0
        for email in ctx.config.owned_emails:
            response = await ctx.http.get(
                f"{API}/breachedaccount/{quote(email)}",
                params={"truncateResponse": "false"},
                headers=headers,
            )
            if response.status_code == 404:  # HIBP's way of saying "not pwned"
                clean += 1
                continue
            check_status(response, self.name)
            data = response.json()
            if not isinstance(data, list):
                raise SourceError("hibp: unexpected response format")
            breaches += [parse_breach(b, "owned-account", (email,)) for b in data
                         if isinstance(b, dict)]
        ctx.notes.append(
            f"{len(ctx.config.owned_emails)} address(es) checked, {clean} not found in any breach"
        )
        return Findings(breaches=breaches)


def _invert(data: Any, domain: str) -> dict[str, set[str]]:
    """{alias: [breach, ...]} -> {breach: {alias@domain, ...}}."""
    if not isinstance(data, dict):
        raise SourceError("hibp: unexpected response format")
    result: dict[str, set[str]] = {}
    for alias, names in data.items():
        if not isinstance(names, list):
            continue
        for name in names:
            result.setdefault(str(name), set()).add(f"{alias}@{domain}".lower())
    return result
