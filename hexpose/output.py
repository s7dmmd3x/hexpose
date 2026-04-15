"""High-level output helpers: tie together export + redaction for the CLI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from hexpose.scanner import ScanResult
from hexpose.export import export, FORMAT_HANDLERS

_DEFAULT_FORMAT = "json"


def write_output(
    result: ScanResult,
    fmt: str = _DEFAULT_FORMAT,
    output_path: Optional[str] = None,
    redact: bool = True,
    redact_mode: str = "partial",
) -> None:
    """Render *result* and write to *output_path* or stdout.

    Parameters
    ----------
    result:
        The :class:`~hexpose.scanner.ScanResult` to serialise.
    fmt:
        One of the supported export formats (json, csv, sarif).
    output_path:
        File path to write to.  ``None`` means stdout.
    redact:
        Whether to redact secret values before writing.
    redact_mode:
        ``'partial'`` or ``'full'`` — passed to the redactor.
    """
    if fmt not in FORMAT_HANDLERS:
        raise ValueError(
            f"Unsupported output format {fmt!r}. "
            f"Available: {sorted(FORMAT_HANDLERS)}"
        )

    rendered = export(result, fmt=fmt, redact=redact, mode=redact_mode)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")


def supported_formats() -> list[str]:
    """Return the list of export format identifiers."""
    return sorted(FORMAT_HANDLERS.keys())
