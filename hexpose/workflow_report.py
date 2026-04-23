"""workflow_report.py – human-readable formatting for WorkflowMatch objects."""
from __future__ import annotations

from typing import List

from hexpose.match_workflow import WorkflowMatch

_STATE_COLOURS = {
    "open": "\033[33m",       # yellow
    "in_review": "\033[36m",  # cyan
    "escalated": "\033[31m",  # red
    "resolved": "\033[32m",   # green
    "wont_fix": "\033[90m",   # dark grey
}
_RESET = "\033[0m"


def _c(text: str, colour: str) -> str:
    return f"{colour}{text}{_RESET}"


def format_workflow_match(wm: WorkflowMatch, *, colour: bool = True) -> str:
    colour_code = _STATE_COLOURS.get(wm.state, "")
    state_str = _c(wm.state, colour_code) if colour else wm.state
    assignee_str = wm.assignee or "unassigned"
    lines = [
        f"  Pattern  : {wm.match.pattern_name}",
        f"  Severity : {wm.match.severity}",
        f"  State    : {state_str}",
        f"  Assignee : {assignee_str}",
        f"  Steps    : {len(wm.transitions)}",
    ]
    return "\n".join(lines)


def format_workflow_report(
    items: List[WorkflowMatch],
    *,
    colour: bool = True,
) -> str:
    if not items:
        return "No workflow items."
    parts = []
    for i, wm in enumerate(items, 1):
        parts.append(f"[{i}]")
        parts.append(format_workflow_match(wm, colour=colour))
    return "\n".join(parts)


def workflow_summary(items: List[WorkflowMatch]) -> str:
    from collections import Counter
    counts: Counter = Counter(wm.state for wm in items)
    if not counts:
        return "workflow: 0 items"
    parts = ", ".join(f"{s}={n}" for s, n in sorted(counts.items()))
    return f"workflow: {len(items)} items ({parts})"
