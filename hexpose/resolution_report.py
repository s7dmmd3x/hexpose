"""Formatting helpers for ResolutionMatch results."""
from __future__ import annotations

from typing import List

from hexpose.match_resolution import ResolutionMatch


_COLOURS = {
    "open": "\033[33m",
    "fixed": "\033[32m",
    "wont_fix": "\033[90m",
    "false_positive": "\033[36m",
    "duplicate": "\033[35m",
}
_RESET = "\033[0m"


def _c(text: str, resolution: str) -> str:
    colour = _COLOURS.get(resolution, "")
    return f"{colour}{text}{_RESET}" if colour else text


def format_resolution_match(rm: ResolutionMatch, *, colour: bool = True) -> str:
    tag = rm.resolution.upper()
    label = _c(f"[{tag}]", rm.resolution) if colour else f"[{tag}]"
    by = f" by {rm.resolved_by}" if rm.resolved_by else ""
    at = f" at {rm.resolved_at.isoformat()}" if rm.resolved_at else ""
    line = f"{label} {rm.match.pattern_name} ({rm.match.severity}){by}{at}"
    if rm.notes:
        notes_str = "; ".join(rm.notes)
        line += f"\n    notes: {notes_str}"
    return line


def format_resolution_report(
    items: List[ResolutionMatch], *, colour: bool = True
) -> str:
    if not items:
        return "No resolution records."
    lines = [format_resolution_match(rm, colour=colour) for rm in items]
    return "\n".join(lines)


def resolution_summary(items: List[ResolutionMatch]) -> str:
    from collections import Counter

    counts: Counter = Counter(rm.resolution for rm in items)
    total = len(items)
    parts = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    return f"Resolution summary ({total} total): {parts}" if parts else "No records."
