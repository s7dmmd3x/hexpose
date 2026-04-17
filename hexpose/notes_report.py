"""Formatting helpers for match notes."""
from __future__ import annotations
from typing import List
from hexpose.match_notes import NotedMatch

try:
    from colorama import Fore, Style
    _COLOR = True
except ImportError:
    _COLOR = False


def _c(text: str, color: str) -> str:
    if _COLOR:
        return f"{color}{text}{Style.RESET_ALL}"
    return text


def format_noted_match(nm: NotedMatch) -> str:
    header = _c(f"[{nm.match.pattern_name}]", Fore.CYAN if _COLOR else "")
    value = _c(nm.match.value, Fore.YELLOW if _COLOR else "")
    lines = [f"{header} {value}"]
    if nm.has_notes():
        for note in nm.notes:
            lines.append(f"  note: {note}")
    else:
        lines.append("  note: (none)")
    return "\n".join(lines)


def format_notes_report(noted: List[NotedMatch]) -> str:
    if not noted:
        return "No matches to annotate."
    sections = [format_noted_match(nm) for nm in noted]
    return "\n\n".join(sections)


def notes_summary(noted: List[NotedMatch]) -> str:
    total = len(noted)
    with_notes = sum(1 for nm in noted if nm.has_notes())
    return f"{with_notes}/{total} matches have analyst notes."
