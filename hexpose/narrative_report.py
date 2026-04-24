"""narrative_report.py — format NarrativeMatch objects for terminal output."""
from __future__ import annotations

from typing import List

from hexpose.match_narrative import NarrativeMatch


def _c(text: str, code: str) -> str:
    """Wrap *text* in an ANSI colour *code*."""
    return f"\033[{code}m{text}\033[0m"


def format_narrative_match(nm: NarrativeMatch) -> str:
    """Return a formatted string for a single NarrativeMatch."""
    lines: List[str] = []
    header = _c(
        f"[{nm.match.pattern_name}] severity={nm.match.severity}  offset={nm.match.offset}",
        "1;36",
    )
    lines.append(header)
    lines.append(_c("  Narrative:", "33") + f" {nm.narrative}")
    if nm.recommendations:
        lines.append(_c("  Recommendations:", "33"))
        for rec in nm.recommendations:
            lines.append(f"    • {rec}")
    return "\n".join(lines)


def format_narrative_report(items: List[NarrativeMatch]) -> str:
    """Return a full report string for a list of NarrativeMatch objects."""
    if not items:
        return _c("No narrative findings.", "2")
    sections = [format_narrative_match(nm) for nm in items]
    divider = _c("-" * 60, "2")
    return ("\n" + divider + "\n").join(sections)


def narrative_summary(items: List[NarrativeMatch]) -> str:
    """Return a one-line summary."""
    count = len(items)
    noun = "finding" if count == 1 else "findings"
    return _c(f"Narrative report: {count} {noun}.", "1")
