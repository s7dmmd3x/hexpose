"""Formatting helpers for AttributedMatch objects."""
from __future__ import annotations

from typing import List

from hexpose.match_attribution import AttributedMatch

_RESET = "\033[0m"
_BOLD = "\033[1m"
_CYAN = "\033[96m"
_YELLOW = "\033[93m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}"


def format_attributed_match(am: AttributedMatch) -> str:
    header = _c(am.match.pattern_name, _BOLD)
    severity = _c(am.match.severity, _YELLOW)
    author_part = _c(am.author, _CYAN)
    team_part = _c(am.team, _CYAN)
    system_part = _c(am.source_system, _CYAN)
    tags_part = ", ".join(am.tags) if am.tags else "-"
    lines = [
        f"  Pattern : {header}",
        f"  Severity: {severity}",
        f"  Author  : {author_part}",
        f"  Team    : {team_part}",
        f"  System  : {system_part}",
        f"  Tags    : {tags_part}",
    ]
    return "\n".join(lines)


def format_attribution_report(matches: List[AttributedMatch]) -> str:
    if not matches:
        return "No attributed matches."
    sections = [format_attributed_match(am) for am in matches]
    return "\n\n".join(sections)


def attribution_summary(matches: List[AttributedMatch]) -> str:
    if not matches:
        return "Attribution summary: 0 matches."
    authors = {am.author for am in matches}
    teams = {am.team for am in matches}
    return (
        f"Attribution summary: {len(matches)} match(es) "
        f"from {len(authors)} author(s) across {len(teams)} team(s)."
    )
