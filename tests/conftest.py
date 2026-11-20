"""Shared fixtures. Every test is hermetic: no real config, no real keys, no network."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from osint_recon.config import KEY_NAMES, Config, load_config
from osint_recon.http import HttpClient
from osint_recon.log import reset_logging
from osint_recon.models import Findings
from osint_recon.ratelimit import RateLimiter
from osint_recon.sources.base import SourceContext

MakeCtx = Callable[..., SourceContext]

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    # A real ~/.config/osint-recon/config.yaml must never leak into tests...
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    # ...nor real API keys exported in the developer's shell.
    for name in KEY_NAMES:
        monkeypatch.delenv(f"OSINT_RECON_{name.upper()}_KEY", raising=False)
    yield
    reset_logging()


@pytest.fixture()
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture()
def config() -> Config:
    """Bundled defaults with zero waits, so rate-limited tests run instantly."""
    cfg = load_config(search_user_config=False)
    fast = {n: replace(s, min_interval=0.0) for n, s in cfg.sources.items()}
    return replace(cfg, sources=fast, http=replace(cfg.http, max_retries=2))


@pytest.fixture()
async def http_client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as client:
        yield client


@pytest.fixture()
def make_ctx(config: Config, http_client: httpx.AsyncClient) -> MakeCtx:
    """Build a SourceContext for one source, without retries or waits."""

    def factory(
        domain: str = "example.com",
        *,
        previous: Findings | None = None,
        cfg: Config | None = None,
        source: str = "test",
    ) -> SourceContext:
        limiter = RateLimiter(0.0, 5)
        http = HttpClient(http_client, limiter, source=source, max_retries=0)
        return SourceContext(domain, cfg or config, http, limiter, previous or Findings())

    return factory
