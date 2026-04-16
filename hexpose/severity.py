"""Severity levels and comparison utilities for hexpose."""

from __future__ import annotations

from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    """Ordered severity levels for secret findings."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse a severity from a case-insensitive string.

        Raises ValueError if the string is not a valid level.
        """
        normalised = value.strip().upper()
        try:
            return cls[normalised]
        except KeyError:
            valid = ", ".join(m.name.lower() for m in cls)
            raise ValueError(
                f"Unknown severity {value!r}. Valid values: {valid}"
            )

    def label(self) -> str:
        """Return a human-readable lowercase label."""
        return self.name.lower()

    def __str__(self) -> str:  # pragma: no cover
        return self.label()


# Convenience constants
LOW = Severity.LOW
MEDIUM = Severity.MEDIUM
HIGH = Severity.HIGH
CRITICAL = Severity.CRITICAL


def parse_severity(value: str) -> Severity:
    """Thin wrapper around Severity.from_string for use in CLI / config."""
    return Severity.from_string(value)


def severity_at_least(level: Severity, minimum: Optional[Severity]) -> bool:
    """Return True if *level* is >= *minimum* (or if minimum is None)."""
    if minimum is None:
        return True
    return level >= minimum


ALL_SEVERITIES: list[Severity] = list(Severity)
