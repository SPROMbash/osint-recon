"""Technology fingerprinting from HTTP responses, driven by ``data/tech_rules.yaml``.

The page is reduced to :class:`PageSignals` (headers, cookie names, generator
meta, script URLs, HTML) and every rule is tested against it. Adding a
technology means editing the YAML, not the code.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

from osint_recon.errors import ConfigError
from osint_recon.models import Technology

MAX_HTML = 500_000  # only the first 500 KB of a page are searched


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    headers: tuple[tuple[str, re.Pattern[str]], ...] = ()
    cookies: tuple[re.Pattern[str], ...] = ()
    meta: re.Pattern[str] | None = None
    scripts: re.Pattern[str] | None = None
    html: re.Pattern[str] | None = None


@dataclass
class PageSignals:
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)  # keys lower-case
    cookies: list[str] = field(default_factory=list)  # cookie names
    generators: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    html: str = ""


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def default_rules() -> tuple[Rule, ...]:
    text = (
        resources.files("osint_recon").joinpath("data").joinpath("tech_rules.yaml")
        .read_text(encoding="utf-8")
    )
    return parse_rules(text)


def parse_rules(text: str) -> tuple[Rule, ...]:
    data = yaml.safe_load(text)
    if not isinstance(data, list):
        raise ConfigError("tech rules: top level must be a list")
    return tuple(_rule(item, i) for i, item in enumerate(data))


def _rule(item: Any, index: int) -> Rule:
    where = f"tech rule #{index}"
    if not isinstance(item, dict) or not isinstance(item.get("name"), str):
        raise ConfigError(f"{where}: needs at least a 'name'")
    where = f"tech rule '{item['name']}'"
    headers = item.get("headers") or {}
    if not isinstance(headers, dict):
        raise ConfigError(f"{where}: 'headers' must be a mapping")
    cookies = item.get("cookies") or []
    if not isinstance(cookies, list):
        raise ConfigError(f"{where}: 'cookies' must be a list")
    return Rule(
        name=item["name"],
        category=str(item.get("category", "Other")),
        headers=tuple((str(h).lower(), _compile(p, where)) for h, p in headers.items()),
        cookies=tuple(_compile(f"(?:{c})", where) for c in cookies),
        meta=_compile_opt(item.get("meta"), where),
        scripts=_compile_opt(item.get("scripts"), where),
        html=_compile_opt(item.get("html"), where),
    )


def _compile(pattern: Any, where: str) -> re.Pattern[str]:
    try:
        return re.compile(str(pattern), re.IGNORECASE)
    except re.error as exc:
        raise ConfigError(f"{where}: invalid regex {pattern!r} ({exc})") from None


def _compile_opt(pattern: Any, where: str) -> re.Pattern[str] | None:
    return None if pattern is None else _compile(pattern, where)


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def detect(page: PageSignals, rules: tuple[Rule, ...] | None = None) -> list[Technology]:
    found: list[Technology] = []
    html = page.html[:MAX_HTML]
    for rule in rules if rules is not None else default_rules():
        version = ""
        evidence: list[str] = []

        for header, pattern in rule.headers:
            value = page.headers.get(header)
            if value and (match := pattern.search(value)):
                evidence.append(f"header {header}: {value[:80]}")
                version = version or _version(match)
        for pattern in rule.cookies:
            for cookie in page.cookies:
                if pattern.fullmatch(cookie):
                    evidence.append(f"cookie {cookie}")
        if rule.meta:
            for generator in page.generators:
                if match := rule.meta.search(generator):
                    evidence.append(f"meta generator: {generator[:80]}")
                    version = version or _version(match)
        if rule.scripts:
            for src in page.scripts:
                if match := rule.scripts.search(src):
                    evidence.append(f"script {src[:100]}")
                    version = version or _version(match)
                    break
        if rule.html and rule.html.search(html):
            evidence.append(f"html matches /{rule.html.pattern[:40]}/")

        if evidence:
            found.append(
                Technology(
                    name=rule.name,
                    category=rule.category,
                    sources=("website",),
                    version=version,
                    evidence=tuple(dict.fromkeys(evidence)),
                )
            )
    return found


def _version(match: re.Match[str]) -> str:
    if match.re.groups and match.group(1):
        return match.group(1)
    return ""
