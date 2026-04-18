"""Formatting helpers for lifecycle match reports."""
from __future__ import annotations

from hexpose.match_lifecycle import LifecycleMatch

_STATE_COLORS = {
    "open": "\033[32m",
    "updated": "\033[33m",
    "resolved": "\033[90m",
}
_RESET = "\033[0m"


def _c(state: str, text: str) -> str:
    return f"{_STATE_COLORS.get(state, '')}{text}{_RESET}"


def format_lifecycle_match(lm: LifecycleMatch) -> str:
    state_str = _c(lm.state, lm.state.upper())
    return (
        f"[{state_str}] {lm.match.pattern_name} "
        f"created={lm.created_at.isoformat()} "
        f"updated={lm.updated_at.isoformat()} "
        + (f"resolved={lm.resolved_at.isoformat()}" if lm.resolved_at else "")
    ).rstrip()


def format_lifecycle_report(items: list[LifecycleMatch]) -> str:
    if not items:
        return "No lifecycle entries."
    return "\n".join(format_lifecycle_match(lm) for lm in items)


def lifecycle_summary(items: list[LifecycleMatch]) -> str:
    counts: dict[str, int] = {"open": 0, "updated": 0, "resolved": 0}
    for lm in items:
        counts[lm.state] = counts.get(lm.state, 0) + 1
    parts = [f"{v} {k}" for k, v in counts.items() if v]
    return "Lifecycle: " + ", ".join(parts) if parts else "Lifecycle: none"
