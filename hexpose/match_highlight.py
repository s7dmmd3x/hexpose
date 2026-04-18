"""Highlight matched values within a line of context."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from hexpose.scanner import Match


_ANSI_RESET = "\033[0m"
_ANSI_COLORS = {
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
}


@dataclass
class HighlightedMatch:
    match: Match
    line: str
    highlighted_line: str
    start_in_line: int
    end_in_line: int

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "line": self.line,
            "highlighted_line": self.highlighted_line,
            "start_in_line": self.start_in_line,
            "end_in_line": self.end_in_line,
        }


def _colorize(text: str, color: str = "red", bold: bool = True) -> str:
    prefix = (_ANSI_COLORS.get("bold", "") if bold else "") + _ANSI_COLORS.get(color, "")
    return f"{prefix}{text}{_ANSI_RESET}"


def highlight_match(
    match: Match,
    source: bytes,
    color: str = "red",
    bold: bool = True,
) -> HighlightedMatch:
    """Locate the match within its source line and return a HighlightedMatch."""
    try:
        text = source.decode("utf-8", errors="replace")
    except Exception:
        text = repr(source)

    lines = text.splitlines(keepends=True)
    abs_start = match.offset
    abs_end = abs_start + len(match.value)

    cursor = 0
    for line in lines:
        line_end = cursor + len(line)
        if cursor <= abs_start < line_end:
            start_in_line = abs_start - cursor
            end_in_line = min(abs_end - cursor, len(line))
            stripped = line.rstrip("\n\r")
            before = stripped[:start_in_line]
            matched = stripped[start_in_line:end_in_line]
            after = stripped[end_in_line:]
            highlighted = before + _colorize(matched, color=color, bold=bold) + after
            return HighlightedMatch(
                match=match,
                line=stripped,
                highlighted_line=highlighted,
                start_in_line=start_in_line,
                end_in_line=end_in_line,
            )
        cursor = line_end

    # Fallback: match not found in any line
    return HighlightedMatch(
        match=match,
        line=match.value,
        highlighted_line=_colorize(match.value, color=color, bold=bold),
        start_in_line=0,
        end_in_line=len(match.value),
    )


def highlight_all(
    matches: list[Match],
    source: bytes,
    color: str = "red",
    bold: bool = True,
) -> list[HighlightedMatch]:
    return [highlight_match(m, source, color=color, bold=bold) for m in matches]
