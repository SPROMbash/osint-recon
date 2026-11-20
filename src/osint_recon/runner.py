"""Run the selected sources concurrently, stage by stage, and consolidate results.

* :func:`plan_sources` decides, for every source, whether it runs and why not
  (disabled, not selected, active outside scope, missing API key). The plan is
  what ``--dry-run`` prints and what the report lists for skipped sources.
* :func:`run_sources` runs stage 1 in parallel, merges, then stage 2 (which
  receives stage-1 findings: subdomains to resolve, document links...). Each
  source gets its own rate limiter; all share one HTTP connection pool.
* A failing source never stops the run: its error is recorded in its
  :class:`SourceResult` and the others carry on.
* Progress is accumulated in a :class:`RunState` owned by the caller, so after
  Ctrl+C the CLI can still write a (partial) report with what finished.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

import httpx

from osint_recon import __version__
from osint_recon.config import Config
from osint_recon.errors import SourceError
from osint_recon.http import HttpClient, make_async_client
from osint_recon.log import get_logger
from osint_recon.models import Findings, Report, SourceResult, merge
from osint_recon.ratelimit import RateLimiter
from osint_recon.sources.base import Source, SourceContext
from osint_recon.sources.crtsh import CrtShSource
from osint_recon.sources.dns import DnsSource
from osint_recon.sources.documents import DocumentsSource
from osint_recon.sources.hackertarget import HackerTargetSource
from osint_recon.sources.hibp import HibpSource
from osint_recon.sources.hunter import HunterSource
from osint_recon.sources.otx import OtxSource
from osint_recon.sources.website import WebsiteSource

log = get_logger(__name__)


def domain_sources() -> list[Source]:
    """Every source of a domain scan, in report order."""
    return [
        CrtShSource(), HackerTargetSource(), OtxSource(), HunterSource(), HibpSource(),
        WebsiteSource(), DocumentsSource(), DnsSource(),
    ]


@dataclass(frozen=True)
class PlannedSource:
    source: Source
    runs: bool
    reason: str = ""  # why it does not run


@dataclass
class RunState:
    """Mutable progress, readable even if the run is interrupted."""

    results: list[SourceResult] = field(default_factory=list)
    parts: list[Findings] = field(default_factory=list)

    @property
    def findings(self) -> Findings:
        return merge(self.parts)


def plan_sources(
    config: Config,
    sources: Sequence[Source],
    *,
    active: bool,
    only: set[str] | None = None,
) -> list[PlannedSource]:
    plan: list[PlannedSource] = []
    for source in sources:
        reason = ""
        if only is not None and source.name not in only:
            reason = "not selected (--sources)"
        elif not config.sources[source.name].enabled:
            reason = "disabled in config"
        elif source.active and not active:
            reason = "active source: passive-only run"
        elif source.key_name and not config.key(source.key_name):
            reason = f"needs an API key (OSINT_RECON_{source.key_name.upper()}_KEY)"
        plan.append(PlannedSource(source, runs=not reason, reason=reason))
    return plan


async def run_sources(
    target: str,
    config: Config,
    plan: Sequence[PlannedSource],
    state: RunState,
    *,
    client: httpx.AsyncClient | None = None,
) -> None:
    """Execute the plan, filling ``state`` as sources finish."""
    for item in plan:
        if not item.runs:
            state.results.append(SourceResult(item.source.name, "skipped", item.reason))

    running = [p.source for p in plan if p.runs]
    own_client = client is None
    http_client = client or make_async_client(config)
    try:
        for stage in sorted({s.stage for s in running}):
            previous = state.findings
            await asyncio.gather(
                *(
                    _run_one(s, target, config, http_client, previous, state)
                    for s in running
                    if s.stage == stage
                )
            )
    finally:
        if own_client:
            await http_client.aclose()


async def _run_one(
    source: Source,
    target: str,
    config: Config,
    client: httpx.AsyncClient,
    previous: Findings,
    state: RunState,
) -> None:
    settings = config.sources[source.name]
    limiter = RateLimiter(settings.min_interval, settings.concurrency)
    http = HttpClient(
        client, limiter, source=source.name,
        max_retries=config.http.max_retries, max_retry_wait=config.http.max_retry_wait,
    )
    ctx = SourceContext(target, config, http, limiter, previous)
    log.info("[%s] started", source.name)
    start = time.monotonic()
    findings: Findings | None = None
    error = ""
    try:
        findings = await source.collect(ctx)
    except SourceError as exc:
        error = str(exc)
    except httpx.HTTPError as exc:
        error = f"{source.name}: {type(exc).__name__}"
    except Exception as exc:  # a bug in one source must not kill the whole run
        log.debug("[%s] unexpected error", source.name, exc_info=True)
        error = f"{source.name}: unexpected {type(exc).__name__}: {exc}"
    duration = time.monotonic() - start

    message = "; ".join([*ctx.notes, *([error] if error else [])])
    if findings is not None:
        state.parts.append(findings)
        state.results.append(
            SourceResult(source.name, "ok", message, duration, findings.count())
        )
        log.info("[%s] done in %.1fs: %d finding(s)", source.name, duration, findings.count())
    else:
        state.results.append(SourceResult(source.name, "error", message, duration))
        log.warning("[%s] failed: %s", source.name, error)


def build_report(
    target: str,
    kind: str,
    state: RunState,
    plan: Sequence[PlannedSource],
    *,
    active: bool,
    partial: bool = False,
) -> Report:
    """Consolidated report; source results in plan order (unfinished ones marked)."""
    by_name = {r.source: r for r in state.results}
    ordered: list[SourceResult] = []
    for item in plan:
        if not item.runs:  # from the plan itself: correct even if the run never started
            ordered.append(SourceResult(item.source.name, "skipped", item.reason))
            continue
        result = by_name.get(item.source.name)
        if result is None:  # interrupted before it finished
            result = SourceResult(item.source.name, "error", "interrupted before finishing")
        ordered.append(result)
    findings = state.findings
    findings.document_links = []  # internal hand-over, not part of the report
    return Report(
        target=target,
        kind="footprint" if kind == "footprint" else "domain",
        generated=datetime.now().astimezone().replace(microsecond=0),
        tool_version=__version__,
        active=active,
        sources=tuple(ordered),
        findings=findings,
        partial=partial,
    )
