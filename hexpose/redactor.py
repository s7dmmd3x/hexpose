"""Utilities for redacting sensitive values in scan output."""

from __future__ import annotations

import re
from typing import Optional

_REDACT_PLACEHOLDER = "[REDACTED]"
_PARTIAL_SHOW = 4  # characters to reveal at start/end for partial mode


def redact_full(value: str) -> str:
    """Replace the entire value with a placeholder."""
    return _REDACT_PLACEHOLDER


def redact_partial(value: str) -> str:
    """Show first and last N characters; mask the middle."""
    if len(value) <= _PARTIAL_SHOW * 2:
        return _REDACT_PLACEHOLDER
    head = value[:_PARTIAL_SHOW]
    tail = value[-_PARTIAL_SHOW:]
    masked = "*" * min(len(value) - _PARTIAL_SHOW * 2, 8)
    return f"{head}{masked}{tail}"


def redact_value(value: str, mode: str = "partial") -> str:
    """Redact *value* according to *mode* ('full' or 'partial')."""
    if mode == "full":
        return redact_full(value)
    return redact_partial(value)


def redact_line(line: str, value: str, mode: str = "partial") -> str:
    """Return *line* with every occurrence of *value* replaced."""
    if not value:
        return line
    replacement = redact_value(value, mode)
    return line.replace(value, replacement)


def apply_redaction(
    text: str,
    values: list[str],
    mode: str = "partial",
) -> str:
    """Replace all *values* found in *text* using the chosen *mode*."""
    for val in sorted(values, key=len, reverse=True):  # longest first
        if val:
            replacement = redact_value(val, mode)
            text = text.replace(val, replacement)
    return text
