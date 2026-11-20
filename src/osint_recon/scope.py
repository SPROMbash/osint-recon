"""Target validation and authorisation scope.

* :func:`normalize_domain` turns user input (``https://Example.com/path``) into a
  clean registrable-looking hostname, or rejects it.
* :func:`belongs_to` decides if a hostname/email found by a source really belongs
  to the target (sources return noise: other domains in certificates, wildcards...).
* :func:`active_allowed` implements the ethical gate: *active* collection (crawling
  the site, resolving DNS, downloading documents) touches the target's servers, so
  it is only allowed for domains declared in ``scope`` or with ``--authorized``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from osint_recon.errors import InvalidTargetError

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")


def normalize_domain(text: str) -> str:
    """Return a lowercase ASCII (IDNA) domain or raise :class:`InvalidTargetError`."""
    raw = text.strip()
    if "://" in raw:
        raw = urlsplit(raw).hostname or ""
    raw = raw.split("/")[0].split(":")[0].strip(".").lower()
    if raw.startswith("*."):
        raw = raw[2:]

    if not raw:
        raise InvalidTargetError(f"'{text}' is not a domain")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise InvalidTargetError(f"'{text}' is an IP address; osint-recon works on domains")

    try:
        ascii_domain = raw.encode("idna").decode("ascii")
    except UnicodeError:
        raise InvalidTargetError(f"'{text}' is not a valid domain name") from None

    labels = ascii_domain.split(".")
    if len(labels) < 2 or len(ascii_domain) > 253 or not all(_LABEL.match(lb) for lb in labels):
        raise InvalidTargetError(f"'{text}' is not a valid domain name")
    if labels[-1].isdigit():
        raise InvalidTargetError(f"'{text}' is not a valid domain name")
    return ascii_domain


def clean_hostname(name: str) -> str | None:
    """Normalise a hostname found in source data (``*.A.example.com.`` -> ``a.example.com``)."""
    host = name.strip().lower().rstrip(".")
    while host.startswith("*."):
        host = host[2:]
    if not host or " " in host or "@" in host:
        return None
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(lb) for lb in labels):
        return None
    return host


def belongs_to(hostname: str, domain: str) -> bool:
    """True if ``hostname`` is ``domain`` or one of its subdomains."""
    return hostname == domain or hostname.endswith("." + domain)


# Crawled pages are full of strings like "logo@2x.png" (retina image names) that
# look like emails. These "TLDs" are file extensions, never real email domains.
_FILE_EXTENSIONS = frozenset(
    {"png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "bmp", "css", "js", "map"}
)


def email_domain(address: str) -> str | None:
    match = _EMAIL.match(address.strip())
    if not match:
        return None
    domain = match.group(1).lower()
    return None if domain.rsplit(".", 1)[-1] in _FILE_EXTENSIONS else domain


def email_belongs_to(address: str, domain: str) -> bool:
    found = email_domain(address)
    return found is not None and belongs_to(found, domain)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def active_allowed(domain: str, scope: Iterable[str], *, authorized_flag: bool) -> bool:
    """Ethical gate for active collection (see module docstring)."""
    return authorized_flag or any(belongs_to(domain, s) for s in scope)
