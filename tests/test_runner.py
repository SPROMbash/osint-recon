"""Tests for planning, staged concurrent execution and report building."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import ClassVar

import httpx
import pytest

from osint_recon.config import Config
from osint_recon.errors import SourceError
from osint_recon.models import Findings, Subdomain
from osint_recon.runner import (
    RunState,
    build_report,
    domain_sources,
    plan_sources,
    run_sources,
)
from osint_recon.sources.base import Source, SourceContext


class Passive(Source):
    name = "crtsh"
    description = "fake passive"

    async def collect(self, ctx: SourceContext) -> Findings:
        await asyncio.sleep(0)
        ctx.notes.append("fake note")
        return Findings(subdomains=[Subdomain("a.example.com", (self.name,))])


class Failing(Source):
    name = "otx"
    description = "fake failing"

    async def collect(self, ctx: SourceContext) -> Findings:
        raise SourceError("otx: quota exceeded")


class Buggy(Source):
    name = "hackertarget"
    description = "fake buggy"

    async def collect(self, ctx: SourceContext) -> Findings:
        raise ZeroDivisionError("oops")


class Stage2(Source):
    name = "dns"
    description = "fake stage 2"
    active = True
    stage = 2
    seen: ClassVar[list[str]] = []

    async def collect(self, ctx: SourceContext) -> Findings:
        Stage2.seen = [s.name for s in ctx.previous.subdomains]
        return Findings(subdomains=[Subdomain("a.example.com", (self.name,), ("192.0.2.1",))])


class Keyed(Source):
    name = "hunter"
    description = "needs key"
    key_name = "hunter"

    async def collect(self, ctx: SourceContext) -> Findings:  # pragma: no cover
        return Findings()


def test_plan_reasons(config: Config) -> None:
    cfg = replace(config, sources={**config.sources,
                                   "otx": replace(config.sources["otx"], enabled=False)})
    plan = plan_sources(cfg, [Passive(), Failing(), Stage2(), Keyed()], active=False)
    reasons = {p.source.name: (p.runs, p.reason) for p in plan}
    assert reasons["crtsh"] == (True, "")
    assert reasons["otx"] == (False, "disabled in config")
    assert reasons["dns"] == (False, "active source: passive-only run")
    assert reasons["hunter"] == (False, "needs an API key (OSINT_RECON_HUNTER_KEY)")


def test_plan_only_selected(config: Config) -> None:
    plan = plan_sources(config, [Passive(), Failing()], active=True, only={"otx"})
    assert [(p.source.name, p.runs) for p in plan] == [("crtsh", False), ("otx", True)]


def test_domain_sources_cover_config() -> None:
    names = [s.name for s in domain_sources()]
    assert len(names) == len(set(names)) == 8


async def test_run_stages_errors_and_merge(config: Config) -> None:
    plan = plan_sources(config, [Passive(), Failing(), Buggy(), Stage2(), Keyed()], active=True)
    state = RunState()
    async with httpx.AsyncClient() as client:
        await run_sources("example.com", config, plan, state, client=client)

    assert Stage2.seen == ["a.example.com"]  # stage 2 received stage-1 findings
    results = {r.source: r for r in state.results}
    assert results["crtsh"].status == "ok" and results["crtsh"].message == "fake note"
    assert results["otx"].status == "error" and "quota exceeded" in results["otx"].message
    assert "unexpected ZeroDivisionError" in results["hackertarget"].message
    assert results["hunter"].status == "skipped"

    report = build_report("example.com", "domain", state, plan, active=True)
    (sub,) = report.findings.subdomains
    assert sub.sources == ("crtsh", "dns") and sub.addresses == ("192.0.2.1",)
    assert [r.source for r in report.sources] == ["crtsh", "otx", "hackertarget", "dns", "hunter"]
    assert report.partial is False and report.kind == "domain"


async def test_run_creates_and_closes_its_own_client(config: Config) -> None:
    plan = plan_sources(config, [Passive()], active=False)
    state = RunState()
    await run_sources("example.com", config, plan, state)
    assert state.results[0].status == "ok"


def test_build_report_marks_unfinished_sources(config: Config) -> None:
    plan = plan_sources(config, [Passive(), Failing()], active=False)
    state = RunState()  # nothing finished (e.g. Ctrl+C right away)
    report = build_report("example.com", "domain", state, plan, active=False, partial=True)
    assert report.partial is True
    assert all(r.message == "interrupted before finishing" for r in report.sources)


@pytest.mark.parametrize("kind", ["domain", "footprint"])
def test_report_kind(config: Config, kind: str) -> None:
    report = build_report("x", kind, RunState(), [], active=False)
    assert report.kind == kind
