"""Smoke tests running the installed package as a real separate process.

They prove the package starts on its own (imports, bundled YAML data files,
``python -m``) — something in-process CliRunner tests cannot show. None of them
sends network requests: only --version, the scope refusal and a dry run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from osint_recon import __version__


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "osint_recon", *args],
        capture_output=True, text=True, cwd=cwd, timeout=60, check=False,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


def test_version(tmp_path: Path) -> None:
    result = run("--version", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout


def test_scope_refusal_exit_code(tmp_path: Path) -> None:
    result = run("domain", "example.com", cwd=tmp_path)
    assert result.returncode == 4
    assert "not in your authorised scope" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_dry_run_uses_bundled_data(tmp_path: Path) -> None:
    result = run("domain", "example.com", "--authorized", "--dry-run", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "[RUN ] crtsh" in result.stdout
    assert list(tmp_path.iterdir()) == []
