"""Formatting helpers for impact assessment output."""
from __future__ import annotations
from hexpose.match_impact import ImpactedMatch

_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[96m",
    "info": "\033[37m",
}
_RESET = "\033[0m"


def _c(level: str, text: str, color: bool = True) -> str:
    if not color:
        return text
    code = _COLORS.get(level, "")
    return f"{code}{text}{_RESET}"


def format_impacted_match(im: ImpactedMatch, color: bool = True) -> str:
    level_str = _c(im.impact_level, im.impact_level.upper(), color)
    return (
        f"[{level_str}] {im.match.pattern_name} "
        f"@ offset {im.match.offset} "
        f"score={im.impact_score:.3f} — {im.rationale}"
    )


def format_impact_report(items: list[ImpactedMatch], color: bool = True) -> str:
    if not items:
        return "No impact findings."
    lines = [format_impacted_match(i, color=color) for i in items]
    return "\n".join(lines)


def impact_summary(items: list[ImpactedMatch]) -> str:
    from collections import Counter
    counts: Counter = Counter(i.impact_level for i in items)
    parts = ", ".join(f"{lvl}={counts[lvl]}" for lvl in ["critical", "high", "medium", "low", "info"] if lvl in counts)
    return f"Impact summary: {parts}" if parts else "Impact summary: none"
