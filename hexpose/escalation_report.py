"""Human-readable and summary reporting for escalated matches."""
from __future__ import annotations

from typing import List

from hexpose.match_escalation import EscalatedMatch


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_escalated_match(em: EscalatedMatch, *, color: bool = True) -> str:
    """Return a single-line description of an escalated match."""
    flag = "[ESCALATED]" if em.escalated else "[stable]  "
    sev_str = f"{em.previous_severity or 'new'} -> {em.current_severity}"

    if color and em.escalated:
        flag = _c(flag, "31;1")  # bold red
        sev_str = _c(sev_str, "33")

    return (
        f"{flag} "
        f"{em.match.pattern_name:<30} "
        f"sev={sev_str:<22} "
        f"reason={em.reason}"
    )


def format_escalation_report(
    matches: List[EscalatedMatch],
    *,
    color: bool = True,
    only_escalated: bool = False,
) -> str:
    """Format a full escalation report."""
    if not matches:
        return "No matches to report."

    filtered = [m for m in matches if m.escalated] if only_escalated else matches
    if not filtered:
        return "No escalations detected."

    lines = ["=== Escalation Report ==="]
    for em in filtered:
        lines.append(format_escalated_match(em, color=color))
    return "\n".join(lines)


def escalation_summary(matches: List[EscalatedMatch]) -> str:
    """Return a brief summary line."""
    total = len(matches)
    escalated = sum(1 for m in matches if m.escalated)
    return f"Escalation summary: {escalated}/{total} match(es) escalated."
