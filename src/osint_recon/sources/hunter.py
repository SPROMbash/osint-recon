"""Emails (and the names/positions Hunter publishes with them) via Hunter.io (passive, key).

Hunter's domain search returns addresses it has seen publicly for a domain, with
the first/last name and position it associates with each one. Those values are
kept as returned: no further lookups are made about any person.

The free plan allows 25 searches/month and up to 10 results per request, so
results are paginated in pages of 10 up to ``hunter.max_results``. If a later
page is refused (plan limits), the source keeps what it already has.
The API key travels as a query parameter; the HTTP client never logs query
strings and the logging filter masks the key anyway.
"""

from __future__ import annotations

import json
from typing import Any

from osint_recon.errors import SourceError
from osint_recon.models import Email, Findings, Person
from osint_recon.scope import email_belongs_to
from osint_recon.sources.base import Source, SourceContext

URL = "https://api.hunter.io/v2/domain-search"
PAGE_SIZE = 10


class HunterSource(Source):
    name = "hunter"
    description = "Hunter.io domain search: public emails (API key)"
    key_name = "hunter"

    async def collect(self, ctx: SourceContext) -> Findings:
        key = ctx.config.key("hunter")
        wanted = ctx.config.hunter_max_results
        emails: list[Email] = []
        people: list[Person] = []
        offset = 0
        total = 0
        organization = ""

        while offset < wanted:
            limit = min(PAGE_SIZE, wanted - offset)
            params: dict[str, str | int] = {
                "domain": ctx.domain, "api_key": key, "limit": limit, "offset": offset,
            }
            try:
                data = await self._page(ctx, params)
            except SourceError as exc:
                if offset == 0:
                    raise
                ctx.notes.append(f"stopped at {offset} results: {exc}")
                break

            payload = data.get("data") if isinstance(data, dict) else None
            if not isinstance(payload, dict):
                raise SourceError("hunter: unexpected response format")
            organization = organization or str(payload.get("organization") or "")
            raw_meta = data.get("meta")
            meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
            total = int(meta.get("results") or 0)
            entries = payload.get("emails") or []

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                address = str(entry.get("value") or "").strip().lower()
                if not email_belongs_to(address, ctx.domain):
                    continue
                full_name = " ".join(
                    str(entry.get(k) or "").strip() for k in ("first_name", "last_name")
                ).strip()
                position = str(entry.get("position") or "").strip()
                emails.append(Email(address, (self.name,), full_name, position))
                if full_name:
                    people.append(Person(full_name, (self.name,), position))

            offset += len(entries)
            if len(entries) < limit or offset >= total:
                break

        ctx.notes.append(
            f"{len(emails)} email(s) retrieved of {total} known to Hunter"
            + (f" (organisation: {organization})" if organization else "")
        )
        return Findings(emails=emails, people=people)

    async def _page(self, ctx: SourceContext, params: dict[str, str | int]) -> dict[str, Any]:
        response = await ctx.http.get(URL, params=params)
        if response.status_code == 401:
            raise SourceError("hunter: invalid API key (HTTP 401)", status=401)
        if response.status_code >= 400:
            raise SourceError(
                f"hunter: HTTP {response.status_code}: {_error_details(response.text)}",
                status=response.status_code,
            )
        try:
            data = response.json()
        except ValueError:
            raise SourceError("hunter: response is not valid JSON") from None
        if not isinstance(data, dict):
            raise SourceError("hunter: unexpected response format")
        return data


def _error_details(body: str) -> str:
    """Hunter errors look like {"errors": [{"id": ..., "details": "..."}]}."""
    try:
        errors = json.loads(body).get("errors") or []
        return "; ".join(str(e.get("details") or e.get("id")) for e in errors)[:200] or "error"
    except (ValueError, AttributeError):
        return "error"
