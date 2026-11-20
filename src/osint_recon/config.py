"""Load and validate the YAML configuration.

Layers: bundled ``data/default_config.yaml`` <- user file (``--config`` or
``$XDG_CONFIG_HOME/osint-recon/config.yaml``) <- environment variables for API
keys (``OSINT_RECON_<NAME>_KEY``). The result is a tree of frozen dataclasses.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from osint_recon import __version__
from osint_recon.errors import ConfigError, InvalidTargetError
from osint_recon.scope import email_domain, normalize_domain

APP_DIR_NAME = "osint-recon"
CONFIG_FILE_NAME = "config.yaml"
SOURCE_NAMES = ("crtsh", "hackertarget", "otx", "hunter", "hibp", "website", "documents", "dns")
KEY_NAMES = ("hunter", "hibp", "otx")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


@dataclass(frozen=True)
class SourceSettings:
    enabled: bool
    min_interval: float
    concurrency: int


@dataclass(frozen=True)
class HttpSettings:
    timeout: float
    max_retries: int
    max_retry_wait: float
    user_agent: str


@dataclass(frozen=True)
class CrawlSettings:
    max_pages: int
    max_depth: int
    max_documents: int
    max_document_mb: float


@dataclass(frozen=True)
class Config:
    output_dir: Path
    log_level: str
    scope: tuple[str, ...]
    owned_emails: tuple[str, ...]
    api_keys: dict[str, str]
    http: HttpSettings
    sources: dict[str, SourceSettings]
    crawl: CrawlSettings
    dns_max_hosts: int
    hunter_max_results: int
    origins: tuple[str, ...]

    def key(self, name: str) -> str:
        return self.api_keys.get(name, "")

    @property
    def secrets(self) -> tuple[str, ...]:
        """All configured API keys (for masking in logs)."""
        return tuple(v for v in self.api_keys.values() if v)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def user_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_DIR_NAME / CONFIG_FILE_NAME


def load_config(path: Path | None = None, *, search_user_config: bool = True) -> Config:
    raw = _parse_yaml(_bundled_text(), "<bundled defaults>")
    origins = ["<bundled defaults>"]

    user_file: Path | None = None
    if path is not None:
        user_file = path.expanduser()
        if not user_file.is_file():
            raise ConfigError(f"Config file not found: {user_file}")
    elif search_user_config and user_config_path().is_file():
        user_file = user_config_path()

    if user_file is not None:
        raw = _merge(raw, _parse_yaml(user_file.read_text(encoding="utf-8"), str(user_file)))
        origins.append(str(user_file))

    env_keys = {
        name: value
        for name in KEY_NAMES
        if (value := os.environ.get(f"OSINT_RECON_{name.upper()}_KEY", "").strip())
    }
    if env_keys:
        origins.append("environment (" + ", ".join(sorted(env_keys)) + ")")

    return _build(raw, env_keys, tuple(origins))


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _bundled_text() -> str:
    return (
        resources.files("osint_recon")
        .joinpath("data")
        .joinpath("default_config.yaml")
        .read_text(encoding="utf-8")
    )


def _parse_yaml(text: str, origin: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)  # safe_load: never builds arbitrary Python objects
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {origin}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{origin}: top level must be a mapping")
    return data


_NESTED = ("sources", "api_keys", "http", "crawl", "dns", "hunter")


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Shallow merge; nested sections are merged one level deeper (sources by name)."""
    result = dict(base)
    for key, value in override.items():
        if key in _NESTED and isinstance(value, dict) and isinstance(base.get(key), dict):
            merged = dict(base[key])
            for sub_key, sub_value in value.items():
                if key == "sources" and isinstance(sub_value, dict) and isinstance(
                    merged.get(sub_key), dict
                ):
                    merged[sub_key] = {**merged[sub_key], **sub_value}
                else:
                    merged[sub_key] = sub_value
            result[key] = merged
        else:
            result[key] = value
    return result


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def _build(raw: dict[str, Any], env_keys: dict[str, str], origins: tuple[str, ...]) -> Config:
    log_level = _str(raw, "log_level").upper()
    if log_level not in LOG_LEVELS:
        raise ConfigError(f"'log_level' must be one of {', '.join(LOG_LEVELS)}")

    scope = tuple(_domain(d, "scope") for d in _str_list(raw, "scope"))
    owned = tuple(_owned_email(e) for e in _str_list(raw, "owned_emails"))

    keys_raw = _section(raw, "api_keys")
    unknown = set(keys_raw) - set(KEY_NAMES)
    if unknown:
        raise ConfigError(f"Unknown api_keys: {', '.join(sorted(unknown))}")
    api_keys = {name: str(keys_raw.get(name) or "").strip() for name in KEY_NAMES}
    api_keys.update(env_keys)  # environment wins

    http_raw = _section(raw, "http")
    user_agent = _str(http_raw, "user_agent", "http").replace("{version}", __version__)
    http = HttpSettings(
        timeout=_number(http_raw, "timeout", "http", minimum=1),
        max_retries=int(_number(http_raw, "max_retries", "http", minimum=0)),
        max_retry_wait=_number(http_raw, "max_retry_wait", "http", minimum=0),
        user_agent=user_agent,
    )

    sources_raw = _section(raw, "sources")
    unknown = set(sources_raw) - set(SOURCE_NAMES)
    if unknown:
        raise ConfigError(
            f"Unknown source(s) in 'sources': {', '.join(sorted(unknown))}. "
            f"Known: {', '.join(SOURCE_NAMES)}"
        )
    sources = {name: _source(sources_raw, name) for name in SOURCE_NAMES}

    crawl_raw = _section(raw, "crawl")
    crawl = CrawlSettings(
        max_pages=int(_number(crawl_raw, "max_pages", "crawl", minimum=1)),
        max_depth=int(_number(crawl_raw, "max_depth", "crawl", minimum=0)),
        max_documents=int(_number(crawl_raw, "max_documents", "crawl", minimum=0)),
        max_document_mb=_number(crawl_raw, "max_document_mb", "crawl", minimum=0.1),
    )

    return Config(
        output_dir=Path(_str(raw, "output_dir")).expanduser(),
        log_level=log_level,
        scope=scope,
        owned_emails=owned,
        api_keys=api_keys,
        http=http,
        sources=sources,
        crawl=crawl,
        dns_max_hosts=int(_number(_section(raw, "dns"), "max_hosts", "dns", minimum=1)),
        hunter_max_results=int(
            _number(_section(raw, "hunter"), "max_results", "hunter", minimum=1)
        ),
        origins=origins,
    )


def _source(sources_raw: dict[str, Any], name: str) -> SourceSettings:
    where = f"sources.{name}"
    body = sources_raw.get(name)
    if not isinstance(body, dict):
        raise ConfigError(f"'{where}' must be a mapping")
    enabled = body.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError(f"'{where}.enabled' must be true or false")
    return SourceSettings(
        enabled=enabled,
        min_interval=_number(body, "min_interval", where, minimum=0),
        concurrency=int(_number(body, "concurrency", where, minimum=1)),
    )


def _get(mapping: dict[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise ConfigError(f"Missing required key '{where + '.' if where else ''}{key}'")
    return mapping[key]


def _section(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = _get(raw, key, "")
    if not isinstance(value, dict):
        raise ConfigError(f"'{key}' must be a mapping")
    return value


def _str(mapping: dict[str, Any], key: str, where: str = "") -> str:
    value = _get(mapping, key, where)
    if not isinstance(value, str):
        raise ConfigError(f"'{where + '.' if where else ''}{key}' must be a string")
    return value


def _str_list(mapping: dict[str, Any], key: str) -> list[str]:
    value = _get(mapping, key, "")
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"'{key}' must be a list of strings")
    return value


def _number(mapping: dict[str, Any], key: str, where: str, *, minimum: float) -> float:
    value = _get(mapping, key, where)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"'{where}.{key}' must be a number")
    if value < minimum:
        raise ConfigError(f"'{where}.{key}' must be >= {minimum}")
    return float(value)


def _domain(value: str, where: str) -> str:
    try:
        return normalize_domain(value)
    except InvalidTargetError as exc:
        raise ConfigError(f"'{where}': {exc}") from None


def _owned_email(value: str) -> str:
    if email_domain(value) is None:
        raise ConfigError(f"'owned_emails': '{value}' is not a valid email address")
    return value.strip().lower()
