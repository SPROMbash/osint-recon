"""End-to-end CLI tests. respx intercepts every HTTP request: nothing reaches the network.

With respx's default ``assert_all_mocked``, any request to an unmocked URL fails
the test, which also proves that dry runs and refused runs send nothing.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner, Result

from osint_recon import __version__, cli
from osint_recon.models import Findings, SourceResult, Subdomain
from osint_recon.runner import RunState
from osint_recon.sources.hibp import API as HIBP

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def write_config(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "config.yaml"
    # zero waits so tests are instant; no retries to keep error tests short
    path.write_text(
        "http: {max_retries: 0}\n"
        "sources:\n"
        + "".join(
            f"  {n}: {{min_interval: 0}}\n"
            for n in ("crtsh", "hackertarget", "otx", "hunter", "hibp", "website", "documents")
        )
        + extra,
        encoding="utf-8",
    )
    return path


def invoke(tmp_path: Path, *args: str, extra: str = "") -> Result:
    cfg = write_config(tmp_path, extra)
    return runner.invoke(
        cli.app, [*args, "--config", str(cfg), "--output-dir", str(tmp_path / "reports")]
    )


def mock_passive(respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, text=(FIXTURES / "crtsh.json").read_text("utf-8"))
    )
    respx_mock.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="API count exceeded - Increase Quota")
    )
    respx_mock.get(url__startswith="https://otx.alienvault.com/").mock(
        return_value=httpx.Response(
            200, text=(FIXTURES / "otx_passive_dns.json").read_text("utf-8")
        )
    )
    respx_mock.get(f"{HIBP}/breaches").mock(
        return_value=httpx.Response(
            200, text=json.dumps(json.loads((FIXTURES / "hibp_breaches.json").read_text())[:1])
        )
    )


def reports(tmp_path: Path, suffix: str) -> list[Path]:
    return sorted((tmp_path / "reports").glob(f"*.{suffix}"))


# --------------------------------------------------------------------------- #
# Basics
# --------------------------------------------------------------------------- #
def test_help_and_version() -> None:
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    for word in ("domain", "footprint", "sources", "authorised"):
        assert word in result.output
    assert __version__ in runner.invoke(cli.app, ["--version"]).output


def test_domain_help_mentions_scope() -> None:
    result = runner.invoke(cli.app, ["domain", "--help"])
    for option in ("--passive-only", "--authorized", "--redact-people", "--dry-run", "--sources"):
        assert option in result.output


def test_sources_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSINT_RECON_HUNTER_KEY", "hunter-key-123456")
    result = runner.invoke(cli.app, ["sources", "--config", str(write_config(tmp_path))])
    assert result.exit_code == 0
    lines = {line.split()[0]: line for line in result.output.splitlines()[1:]}
    assert "ready" in lines["hunter"]
    assert "active" in lines["website"]
    assert "ready" in lines["hibp"]  # works without key (service breaches)


# --------------------------------------------------------------------------- #
# Ethical gate and dry run
# --------------------------------------------------------------------------- #
def test_active_run_outside_scope_is_refused(tmp_path: Path, respx_mock: respx.MockRouter) -> None:
    result = invoke(tmp_path, "domain", "example.com")
    assert result.exit_code == 4
    assert "not in your authorised scope" in result.output
    assert "--passive-only" in result.output
    assert not (tmp_path / "reports").exists()  # nothing written, nothing sent


def test_dry_run_sends_nothing(tmp_path: Path, respx_mock: respx.MockRouter) -> None:
    result = invoke(tmp_path, "domain", "https://Example.com/", "--authorized", "--dry-run")
    assert result.exit_code == 0, result.output
    assert "DRY RUN" in result.output and "domain example.com" in result.output
    assert "[RUN ] website" in result.output
    assert "[skip] hunter" in result.output and "OSINT_RECON_HUNTER_KEY" in result.output
    assert not (tmp_path / "reports").exists()


def test_dry_run_passive_only(tmp_path: Path, respx_mock: respx.MockRouter) -> None:
    result = invoke(tmp_path, "domain", "example.com", "--passive-only", "--dry-run")
    assert result.exit_code == 0
    assert "[skip] website" in result.output and "passive-only run" in result.output


def test_scope_in_config_allows_active(tmp_path: Path, respx_mock: respx.MockRouter) -> None:
    result = invoke(tmp_path, "domain", "shop.example.com", "--dry-run",
                    extra="scope: [example.com]\n")
    assert result.exit_code == 0
    assert "passive + active" in result.output


def test_selecting_only_passive_sources_needs_no_scope(
    tmp_path: Path, respx_mock: respx.MockRouter
) -> None:
    result = invoke(tmp_path, "domain", "example.com", "-s", "crtsh,hibp", "--dry-run")
    assert result.exit_code == 0
    assert "[RUN ] crtsh" in result.output and "[skip] otx" in result.output


@pytest.mark.parametrize(
    ("args", "code", "message"),
    [
        (["domain", "not a domain", "--passive-only"], 2, "not a valid domain"),
        (["domain", "10.0.0.1", "--passive-only"], 2, "IP address"),
        (["domain", "example.com", "-s", "google"], 2, "Unknown source(s): google"),
        (["footprint"], 2, "No 'owned_emails'"),
    ],
)
def test_input_errors(
    tmp_path: Path, respx_mock: respx.MockRouter, args: list[str], code: int, message: str
) -> None:
    result = invoke(tmp_path, *args)
    assert result.exit_code == code, result.output
    assert message in result.output
    assert "Traceback" not in result.output


def test_footprint_without_key(tmp_path: Path, respx_mock: respx.MockRouter) -> None:
    result = invoke(tmp_path, "footprint", extra="owned_emails: [me@example.com]\n")
    assert result.exit_code == 2
    assert "OSINT_RECON_HIBP_KEY" in result.output


# --------------------------------------------------------------------------- #
# Full runs
# --------------------------------------------------------------------------- #
def test_passive_domain_run_writes_reports(tmp_path: Path, respx_mock: respx.MockRouter) -> None:
    mock_passive(respx_mock)

    result = invoke(tmp_path, "domain", "example.com", "--passive-only")

    assert result.exit_code == 0, result.output
    (md,) = reports(tmp_path, "md")
    (js,) = reports(tmp_path, "json")
    data = json.loads(js.read_text(encoding="utf-8"))
    assert data["active_collection"] is False
    names = {s["name"] for s in data["findings"]["subdomains"]}
    assert {"www.example.com", "api.example.com", "blog.example.com"} <= names
    status = {s["source"]: s["status"] for s in data["sources"]}
    assert status["crtsh"] == status["otx"] == status["hibp"] == "ok"
    assert status["hackertarget"] == "error"  # quota message inside HTTP 200
    assert status["website"] == "skipped"
    assert "Example Corp" in md.read_text(encoding="utf-8")  # service breach
    assert (tmp_path / "reports" / "osint-recon.log").is_file()
    assert "Source hackertarget failed" in result.output


def test_json_only_and_redaction(tmp_path: Path, respx_mock: respx.MockRouter,
                                 monkeypatch: pytest.MonkeyPatch) -> None:
    respx_mock.get("https://api.hunter.io/v2/domain-search").mock(
        return_value=httpx.Response(
            200, text=(FIXTURES / "hunter_page1.json").read_text("utf-8")
        )
    )
    monkeypatch.setenv("OSINT_RECON_HUNTER_KEY", "hunter-secret-key-987654")

    result = invoke(tmp_path, "domain", "example.com", "-s", "hunter", "-f", "json",
                    "--redact-people")

    assert result.exit_code == 0, result.output
    assert reports(tmp_path, "md") == []
    (js,) = reports(tmp_path, "json")
    text = js.read_text(encoding="utf-8")
    assert "jane.smith" not in text and "Jane Smith" not in text
    assert "j***@example.com" in text and '"redacted": true' in text
    log_text = (tmp_path / "reports" / "osint-recon.log").read_text(encoding="utf-8")
    assert "hunter-secret-key-987654" not in log_text + text + result.output


def test_footprint_run(tmp_path: Path, respx_mock: respx.MockRouter,
                       monkeypatch: pytest.MonkeyPatch) -> None:
    catalogue = json.loads((FIXTURES / "hibp_breaches.json").read_text())
    respx_mock.get(f"{HIBP}/breachedaccount/me%40example.com").mock(
        return_value=httpx.Response(200, json=catalogue[1:2])
    )
    monkeypatch.setenv("OSINT_RECON_HIBP_KEY", "hibp-secret-key-123456")

    result = invoke(tmp_path, "footprint", extra="owned_emails: [me@example.com]\n")

    assert result.exit_code == 0, result.output
    (md,) = reports(tmp_path, "md")
    assert md.name.startswith("footprint-")
    content = md.read_text(encoding="utf-8")
    assert "# Digital footprint" in content and "Adobe" in content


def test_all_sources_failing_exits_5(tmp_path: Path, respx_mock: respx.MockRouter) -> None:
    respx_mock.get("https://crt.sh/").mock(return_value=httpx.Response(502))
    result = invoke(tmp_path, "domain", "example.com", "-s", "crtsh")
    assert result.exit_code == 5
    assert "Every source failed" in result.output
    assert reports(tmp_path, "md")  # the report (with the errors) is still written


def test_ctrl_c_writes_partial_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                      respx_mock: respx.MockRouter) -> None:
    async def interrupted(target: str, cfg: Any, plan: Any, state: RunState,
                          **kw: Any) -> None:
        state.parts.append(Findings(subdomains=[Subdomain("www.example.com", ("crtsh",))]))
        state.results.append(SourceResult("crtsh", "ok", "", 0.1, 1))
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_sources", interrupted)
    result = invoke(tmp_path, "domain", "example.com", "-s", "crtsh,otx")

    assert result.exit_code == 130
    (md,) = reports(tmp_path, "md")
    content = md.read_text(encoding="utf-8")
    assert "PARTIAL REPORT" in content and "www.example.com" in content
    assert "| otx | **error** | 0 | 0.0s | interrupted before finishing |" in content
    assert "| website | skipped |" in content  # not selected: skipped, not "interrupted"


def test_unexpected_error_is_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                   respx_mock: respx.MockRouter) -> None:
    def boom(*a: Any, **k: Any) -> Callable[[], None]:
        raise RuntimeError("kaput")

    monkeypatch.setattr(cli, "plan_sources", boom)
    result = invoke(tmp_path, "domain", "example.com", "--passive-only")
    assert result.exit_code == 1
    assert "Unexpected error: RuntimeError: kaput" in result.output
