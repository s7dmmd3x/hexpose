"""Human-readable formatting for LineageMatch objects."""
from __future__ import annotations

from typing import List

from hexpose.match_lineage import LineageMatch


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_lineage_match(lm: LineageMatch) -> str:
    """Single-line summary of a LineageMatch."""
    name = _c(lm.match.pattern_name, "36")
    sev = _c(lm.match.severity, "33")
    steps = " -> ".join(lm.steps) if lm.steps else _c("(none)", "90")
    return f"[{sev}] {name}  lineage: {steps}"


def format_lineage_report(matches: List[LineageMatch]) -> str:
    """Full report for a list of LineageMatch objects."""
    if not matches:
        return _c("No lineage data.", "90")
    lines = [_c("=== Lineage Report ===", "1")]
    for lm in matches:
        lines.append(format_lineage_match(lm))
    return "\n".join(lines)


def lineage_summary(matches: List[LineageMatch]) -> str:
    """One-line summary: total matches and unique steps seen."""
    all_steps: set = set()
    for lm in matches:
        all_steps.update(lm.steps)
    return (
        f"{len(matches)} match(es) tracked across "
        f"{len(all_steps)} unique step(s): {', '.join(sorted(all_steps)) or 'none'}"
    )
