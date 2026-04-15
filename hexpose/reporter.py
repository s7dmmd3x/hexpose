"""Output formatting and reporting for hexpose scan results."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from typing import TextIO

from hexpose.scanner import ScanResult

SEVERITY_COLORS = {
    "critical": "\033[91m",  # bright red
    "high": "\033[31m",     # red
    "medium": "\033[33m",   # yellow
    "low": "\033[36m",      # cyan
    "info": "\033[37m",     # white
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _colorize(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{color}{text}{RESET}"


class Reporter:
    """Formats and writes scan results to a stream."""

    def __init__(self, fmt: str = "text", stream: TextIO = sys.stdout, color: bool = True):
        if fmt not in ("text", "json"):
            raise ValueError(f"Unsupported format: {fmt!r}. Choose 'text' or 'json'.")
        self.fmt = fmt
        self.stream = stream
        self.color = color

    def report(self, result: ScanResult) -> None:
        """Write the scan result to the configured stream."""
        if self.fmt == "json":
            self._report_json(result)
        else:
            self._report_text(result)

    def _report_json(self, result: ScanResult) -> None:
        data = {
            "source": result.source,
            "total_bytes": result.total_bytes,
            "matches": [
                {
                    "pattern_name": m.pattern_name,
                    "severity": m.severity,
                    "offset": m.offset,
                    "value": m.value,
                    "context": m.context,
                }
                for m in result.matches
            ],
        }
        json.dump(data, self.stream, indent=2)
        self.stream.write("\n")

    def _report_text(self, result: ScanResult) -> None:
        header = f"Scan: {result.source}  ({result.total_bytes} bytes)"
        self.stream.write(_colorize(f"{BOLD}{header}{RESET}" if self.color else header, BOLD, self.color) + "\n")
        self.stream.write("-" * len(header) + "\n")

        if not result.matches:
            self.stream.write("  No secrets found.\n")
            return

        for m in result.matches:
            color = SEVERITY_COLORS.get(m.severity, "")
            sev_label = _colorize(f"[{m.severity.upper()}]", color, self.color)
            self.stream.write(
                f"  {sev_label} {m.pattern_name} @ offset {m.offset}\n"
                f"    value  : {m.value}\n"
                f"    context: {m.context}\n"
            )

        self.stream.write(f"\nTotal matches: {len(result.matches)}\n")
