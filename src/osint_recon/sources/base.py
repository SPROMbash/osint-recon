"""Common interface for data sources.

A source is a small class with a few class-level facts and one coroutine:

* ``name`` / ``description``: identification (``name`` matches the YAML key);
* ``active``: True if it touches the target's own servers (crawl, DNS, downloads).
  Active sources only run inside the authorised scope (see ``scope.active_allowed``);
* ``stage``: 1 runs first; stage 2 receives what stage 1 found (e.g. DNS resolves
  the subdomains discovered by the passive sources);
* ``key_name``: API key the source *requires* (it is skipped without it);
* ``collect(ctx)``: does the work and returns :class:`Findings`.

Sources raise :class:`SourceError` for expected problems; the runner records it
and the rest of the sources carry on.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from osint_recon.config import Config
from osint_recon.http import HttpClient
from osint_recon.models import Findings
from osint_recon.ratelimit import RateLimiter


@dataclass
class SourceContext:
    domain: str
    config: Config
    http: HttpClient
    limiter: RateLimiter
    previous: Findings = field(default_factory=Findings)
    #: Short remarks shown in the report next to the source (truncation, wildcard DNS...).
    notes: list[str] = field(default_factory=list)


class Source(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    active: ClassVar[bool] = False
    stage: ClassVar[int] = 1
    key_name: ClassVar[str | None] = None

    @abstractmethod
    async def collect(self, ctx: SourceContext) -> Findings:
        """Gather findings for ``ctx.domain``."""
