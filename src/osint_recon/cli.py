"""Command-line interface.

Commands:

* ``domain TARGET`` — OSINT on a domain / organisation;
* ``footprint``     — your own exposure: your ``owned_emails`` in HIBP;
* ``sources``       — list sources and whether they are ready (keys, config).

Ethical gate: active sources (website crawl, document downloads, DNS) touch the
target's servers and only run if the domain is in ``scope`` (config) or with
``--authorized``; otherwise the user must choose ``--passive-only``.
Every expected failure is an ``OsintError`` turned into a message + exit code.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import replace
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

from osint_recon import __version__
from osint_recon.config import Config, load_config
from osint_recon.errors import AllSourcesFailedError, ConfigError, OsintError, ScopeError
from osint_recon.log import add_file_handler, get_logger, setup_logging
from osint_recon.models import Report
from osint_recon.report.redact import redact_report
from osint_recon.report.writer import write_reports
from osint_recon.runner import (
    PlannedSource,
    RunState,
    build_report,
    domain_sources,
    plan_sources,
    run_sources,
)
from osint_recon.scope import active_allowed, normalize_domain
from osint_recon.sources.hibp import HibpFootprintSource

log = get_logger(__name__)

ETHICS = (
    "Use only for domains/organisations you are authorised to assess, or for your own "
    "digital footprint. It gathers PUBLIC data and does not profile individuals."
)

app = typer.Typer(
    help=f"Asynchronous OSINT aggregator for domains and organisations.\n\n{ETHICS}",
    add_completion=False,
    no_args_is_help=True,
)


class Format(str, Enum):
    md = "md"
    json = "json"
    both = "both"


# Shared options -------------------------------------------------------------
ConfigOpt = Annotated[
    Path | None,
    typer.Option(
        "--config", "-c", help="YAML config (default: ~/.config/osint-recon/config.yaml)."
    ),
]
OutputOpt = Annotated[
    Path | None, typer.Option("--output-dir", "-o", help="Folder for reports and the log file.")
]
FormatOpt = Annotated[Format, typer.Option("--format", "-f", help="Report format.")]
RedactOpt = Annotated[
    bool, typer.Option("--redact-people", help="Mask emails and names in the report.")
]
DryRunOpt = Annotated[
    bool, typer.Option("--dry-run", help="Show which sources would run; send no requests.")
]
VerboseOpt = Annotated[bool, typer.Option("--verbose", "-v", help="Debug output on the console.")]


def _version(value: bool) -> None:
    if value:
        typer.echo(f"osint-recon {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version, is_eager=True, help="Show version and exit."),
    ] = None,
) -> None:
    """Asynchronous OSINT aggregator for domains and organisations."""


# --------------------------------------------------------------------------- #
# domain
# --------------------------------------------------------------------------- #
@app.command()
def domain(
    target: Annotated[str, typer.Argument(help="Domain, e.g. example.com.")],
    sources: Annotated[
        str | None,
        typer.Option("--sources", "-s", help="Comma-separated subset, e.g. crtsh,hibp."),
    ] = None,
    passive_only: Annotated[
        bool,
        typer.Option("--passive-only", help="Only third-party sources; never touch the target."),
    ] = False,
    authorized: Annotated[
        bool,
        typer.Option("--authorized", help="I am authorised to actively probe this domain."),
    ] = False,
    config_path: ConfigOpt = None,
    output_dir: OutputOpt = None,
    fmt: FormatOpt = Format.both,
    redact: RedactOpt = False,
    dry_run: DryRunOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Gather public OSINT about a domain / organisation.

    Only for domains you are authorised to assess. Active sources (website
    crawl, documents, DNS) need the domain in 'scope' or --authorized.
    """
    _guard(lambda: _domain(target, sources, passive_only, authorized, config_path,
                           output_dir, fmt, redact, dry_run, verbose), verbose)


def _domain(
    target: str, sources: str | None, passive_only: bool, authorized: bool,
    config_path: Path | None, output_dir: Path | None, fmt: Format, redact: bool,
    dry_run: bool, verbose: bool,
) -> None:
    cfg = _setup(config_path, output_dir, verbose)
    name = normalize_domain(target)
    only = _parse_sources(sources)
    candidates = domain_sources()

    allowed = active_allowed(name, cfg.scope, authorized_flag=authorized)
    wants_active = any(
        s.active and cfg.sources[s.name].enabled and (only is None or s.name in only)
        for s in candidates
    )
    if wants_active and not allowed and not passive_only:
        raise ScopeError(
            f"'{name}' is not in your authorised scope. Active sources (website, documents, "
            "dns) would contact its servers. Add it to 'scope' in your config, pass "
            "--authorized if you ARE authorised, or use --passive-only."
        )
    active = allowed and not passive_only
    plan = plan_sources(cfg, candidates, active=active, only=only)

    if dry_run:
        _print_plan(f"domain {name}", plan, cfg, active)
        return
    _execute(name, "domain", cfg, plan, active=active, fmt=fmt, redact=redact)


# --------------------------------------------------------------------------- #
# footprint
# --------------------------------------------------------------------------- #
@app.command()
def footprint(
    config_path: ConfigOpt = None,
    output_dir: OutputOpt = None,
    fmt: FormatOpt = Format.both,
    redact: RedactOpt = False,
    dry_run: DryRunOpt = False,
    verbose: VerboseOpt = False,
) -> None:
    """Check YOUR OWN email addresses ('owned_emails' in the config) against HIBP."""
    _guard(lambda: _footprint(config_path, output_dir, fmt, redact, dry_run, verbose), verbose)


def _footprint(
    config_path: Path | None, output_dir: Path | None, fmt: Format, redact: bool,
    dry_run: bool, verbose: bool,
) -> None:
    cfg = _setup(config_path, output_dir, verbose)
    if not cfg.owned_emails:
        raise ConfigError("No 'owned_emails' in the config: add your own addresses first.")
    plan = plan_sources(cfg, [HibpFootprintSource()], active=False)
    if dry_run:
        _print_plan(f"footprint ({len(cfg.owned_emails)} owned address(es))", plan, cfg, False)
        return
    if not plan[0].runs:
        raise ConfigError(f"footprint cannot run: {plan[0].reason}")
    _execute("footprint", "footprint", cfg, plan, active=False, fmt=fmt, redact=redact)


# --------------------------------------------------------------------------- #
# sources
# --------------------------------------------------------------------------- #
@app.command("sources")
def list_sources(config_path: ConfigOpt = None) -> None:
    """List data sources and whether they are ready to use."""
    _guard(lambda: _list_sources(config_path), False)


def _list_sources(config_path: Path | None) -> None:
    cfg = load_config(config_path)
    typer.echo(f"{'SOURCE':<13} {'TYPE':<8} {'STAGE':<6} {'STATUS':<42} DESCRIPTION")
    for item in plan_sources(cfg, domain_sources(), active=True):
        kind = "active" if item.source.active else "passive"
        status = "ready" if item.runs else item.reason
        typer.echo(
            f"{item.source.name:<13} {kind:<8} {item.source.stage:<6} {status:<42} "
            f"{item.source.description}"
        )


# --------------------------------------------------------------------------- #
# Shared machinery
# --------------------------------------------------------------------------- #
def _guard(action: Callable[[], None], verbose: bool) -> None:
    """Run a command body, mapping expected errors to exit codes."""
    setup_logging("DEBUG" if verbose else "INFO")
    try:
        action()
    except typer.Exit:
        raise  # deliberate exit codes (e.g. 130 after a partial report); Exit IS an Exception
    except OsintError as exc:
        log.error("%s", exc)
        raise typer.Exit(exc.exit_code) from None
    except KeyboardInterrupt:
        log.error("Interrupted by user.")
        raise typer.Exit(130) from None
    except Exception as exc:
        log.debug("Unexpected error", exc_info=True)
        log.error("Unexpected error: %s: %s (re-run with -v for details)", type(exc).__name__, exc)
        raise typer.Exit(1) from None


def _setup(config_path: Path | None, output_dir: Path | None, verbose: bool) -> Config:
    cfg = load_config(config_path)
    if output_dir is not None:
        cfg = replace(cfg, output_dir=output_dir.expanduser())
    setup_logging("DEBUG" if verbose else cfg.log_level, secrets=cfg.secrets)
    log.debug("Config: %s", ", ".join(cfg.origins))
    return cfg


def _parse_sources(text: str | None) -> set[str] | None:
    if text is None:
        return None
    names = {s.strip().lower() for s in text.split(",") if s.strip()}
    known = {s.name for s in domain_sources()}
    unknown = names - known
    if unknown or not names:
        raise ConfigError(
            f"Unknown source(s): {', '.join(sorted(unknown)) or '(none given)'}. "
            f"Known: {', '.join(sorted(known))}"
        )
    return names


def _execute(
    target: str, kind: str, cfg: Config, plan: list[PlannedSource], *,
    active: bool, fmt: Format, redact: bool,
) -> None:
    if not any(p.runs for p in plan):
        raise ConfigError("No source can run with the current options and configuration.")
    add_file_handler(cfg.output_dir / "osint-recon.log", secrets=cfg.secrets)
    log.info("osint-recon %s: %s (%s collection)", __version__, target,
             "passive + active" if active else "passive")

    state = RunState()
    partial = False
    try:
        asyncio.run(run_sources(target, cfg, plan, state))
    except KeyboardInterrupt:
        partial = True
        log.warning("Interrupted: writing a PARTIAL report with what finished.")

    report = build_report(target, kind, state, plan, active=active, partial=partial)
    if redact:
        report = redact_report(report)
    formats = ["md", "json"] if fmt is Format.both else [fmt.value]
    paths = write_reports(report, cfg.output_dir, formats)
    _print_summary(report, paths)

    if partial:
        raise typer.Exit(130)
    ran = [r for r in report.sources if r.status != "skipped"]
    if ran and all(r.status == "error" for r in ran):
        raise AllSourcesFailedError("Every source failed; see the report for the reasons.")


def _print_plan(title: str, plan: list[PlannedSource], cfg: Config, active: bool) -> None:
    echo = typer.echo
    echo(f"DRY RUN: no request will be sent.\n\n  Target      {title}")
    echo(f"  Collection  {'passive + active' if active else 'passive only'}")
    echo(f"  Reports     {cfg.output_dir}\n")
    for item in plan:
        settings = cfg.sources[item.source.name]
        state = "RUN " if item.runs else "skip"
        detail = (
            f"every {settings.min_interval:g}s, x{settings.concurrency}" if item.runs
            else item.reason
        )
        kind = "active " if item.source.active else "passive"
        echo(f"  [{state}] {item.source.name:<13} {kind}  {detail}")


def _print_summary(report: Report, paths: list[Path]) -> None:
    f = report.findings
    log.info(
        "Found: %d subdomains, %d emails, %d people, %d technologies, %d documents, %d breaches",
        len(f.subdomains), len(f.emails), len(f.people), len(f.technologies),
        len(f.documents), len(f.breaches),
    )
    for result in report.sources:
        if result.status == "error":
            log.warning("Source %s failed: %s", result.source, result.message)
    for path in paths:
        log.info("Report: %s", path)
