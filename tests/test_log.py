"""Tests for logging, especially secret masking."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from osint_recon.log import (
    LOGGER_NAME,
    MASK,
    add_file_handler,
    get_logger,
    mask_secrets,
    setup_logging,
)

KEY = "hunter-super-secret-key-42"


def test_console_prefixes(capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("INFO")
    log = get_logger("x")
    log.debug("hidden")
    log.info("hello")
    log.warning("careful")
    err = capsys.readouterr().err
    assert "[*] hello" in err and "[!] careful" in err and "hidden" not in err


def test_secrets_masked_on_console_and_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    setup_logging("DEBUG", secrets=[KEY])
    log_file = add_file_handler(tmp_path / "run.log", secrets=[KEY])
    log = get_logger("hunter")

    log.debug("GET https://api.hunter.io/v2/domain-search?api_key=%s&domain=x", KEY)
    try:
        raise RuntimeError(f"connection failed for ...?api_key={KEY}")
    except RuntimeError as exc:
        log.error("boom: %s", exc)

    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()
    console = capsys.readouterr().err
    content = log_file.read_text(encoding="utf-8")
    for text in (console, content):
        assert KEY not in text
        assert f"api_key={MASK}" in text


def test_short_values_are_not_treated_as_secrets() -> None:
    setup_logging(secrets=["abc"])  # would mask random words otherwise
    handler = logging.getLogger(LOGGER_NAME).handlers[0]
    record = logging.LogRecord("x", logging.INFO, "f", 1, "abc def", None, None)
    for flt in handler.filters:
        assert isinstance(flt, logging.Filter) and flt.filter(record)
    assert record.getMessage() == "abc def"


def test_mask_secrets_helper() -> None:
    assert mask_secrets("a KEY1234 b KEY1234", ["KEY1234"]) == f"a {MASK} b {MASK}"


def test_setup_is_idempotent() -> None:
    setup_logging()
    setup_logging()
    assert len(logging.getLogger(LOGGER_NAME).handlers) == 1


def test_logger_names() -> None:
    assert get_logger().name == "osint_recon"
    assert get_logger("osint_recon.http").name == "osint_recon.http"
    assert get_logger("dns").name == "osint_recon.dns"
