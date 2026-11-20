"""Exception hierarchy.

Expected failures subclass :class:`OsintError` and carry an ``exit_code``; the
CLI turns them into a clean message. :class:`SourceError` is different: it is
raised *inside* one data source and never stops the run. The runner records it
in that source's result and the other sources carry on.
"""

from __future__ import annotations


class OsintError(Exception):
    """Base class for expected, user-facing errors."""

    exit_code: int = 1


class ConfigError(OsintError):
    """The YAML configuration is missing, unreadable or invalid."""

    exit_code = 2


class InvalidTargetError(OsintError):
    """The domain (or email) given by the user is not valid."""

    exit_code = 2


class ScopeError(OsintError):
    """Active collection requested for a domain you have not declared as authorised."""

    exit_code = 4


class AllSourcesFailedError(OsintError):
    """Every selected source failed: the report would be empty."""

    exit_code = 5


class SourceError(Exception):
    """A single data source failed (bad API key, quota exceeded, invalid response...).

    Not an OsintError on purpose: it is handled by the runner, not the CLI.
    ``status`` is the last HTTP status when the server *did* answer (e.g. 503),
    or None for network failures; callers use it to tell the two apart.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status
