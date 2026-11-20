"""Tests for configuration loading, merging, env keys and validation."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from osint_recon import __version__
from osint_recon.config import SOURCE_NAMES, load_config, user_config_path
from osint_recon.errors import ConfigError


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults() -> None:
    cfg = load_config(search_user_config=False)
    assert set(cfg.sources) == set(SOURCE_NAMES)
    assert cfg.sources["hibp"].min_interval == 6.5  # HIBP Pwned 1: 10 req/min
    assert cfg.scope == () and cfg.owned_emails == ()
    assert cfg.api_keys == {"hunter": "", "hibp": "", "otx": ""}
    assert cfg.secrets == ()
    assert __version__ in cfg.http.user_agent and "{version}" not in cfg.http.user_agent


def test_user_file_merges_sources_by_name(tmp_path: Path) -> None:
    cfg = load_config(
        write(
            tmp_path / "c.yaml",
            "scope: [Example.COM, https://corp.example.org/x]\n"
            "owned_emails: [Me@Example.com]\n"
            "sources:\n  crtsh: {enabled: false}\n"
            "crawl: {max_pages: 5}\n",
        )
    )
    assert cfg.scope == ("example.com", "corp.example.org")  # normalised
    assert cfg.owned_emails == ("me@example.com",)
    assert cfg.sources["crtsh"].enabled is False
    assert cfg.sources["crtsh"].min_interval == 2.0  # untouched keys kept
    assert cfg.crawl.max_pages == 5 and cfg.crawl.max_depth == 2


def test_env_keys_take_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSINT_RECON_HUNTER_KEY", "env-hunter-key-123")
    cfg = load_config(write(tmp_path / "c.yaml", "api_keys: {hunter: file-key-000000}\n"))
    assert cfg.key("hunter") == "env-hunter-key-123"
    assert cfg.secrets == ("env-hunter-key-123",)
    assert any("environment (hunter)" in o for o in cfg.origins)
    assert "env-hunter-key-123" not in " ".join(cfg.origins)  # never the value


def test_user_config_found_in_xdg() -> None:
    write(user_config_path(), "log_level: debug\n")
    assert load_config().log_level == "DEBUG"


def test_missing_and_invalid_files(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")
    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_config(write(tmp_path / "bad.yaml", "scope: [unclosed\n"))
    with pytest.raises(ConfigError, match="top level"):
        load_config(write(tmp_path / "list.yaml", "- a\n"))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("log_level: LOUD\n", "log_level"),
        ("scope: [not a domain]\n", "'scope'"),
        ("scope: example.com\n", "'scope' must be a list"),
        ("owned_emails: [nobody]\n", "not a valid email"),
        ("api_keys: {shodan: x}\n", "Unknown api_keys: shodan"),
        ("sources: {google: {enabled: true}}\n", "Unknown source(s) in 'sources': google"),
        ("sources: {crtsh: {enabled: 'yes'}}\n", "'sources.crtsh.enabled' must be true or false"),
        ("sources: {crtsh: {min_interval: -1}}\n", "'sources.crtsh.min_interval' must be >= 0"),
        ("sources: {crtsh: {concurrency: 0}}\n", "'sources.crtsh.concurrency' must be >= 1"),
        ("sources: {crtsh: off}\n", "'sources.crtsh' must be a mapping"),
        ("http: {timeout: fast}\n", "'http.timeout' must be a number"),
        ("crawl: {max_pages: true}\n", "'crawl.max_pages' must be a number"),
        ("crawl: 5\n", "'crawl' must be a mapping"),
        ("output_dir: 5\n", "'output_dir' must be a string"),
    ],
)
def test_validation_errors(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=re.escape(message)):
        load_config(write(tmp_path / "c.yaml", text))
