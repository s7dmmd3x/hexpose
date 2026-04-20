"""Reporting utilities for sensitivity-classified matches."""
from __future__ import annotations
from hexpose.match_sensitivity import SensitivityMatch

_COLOURS = {
    "public": "\033[32m",
    "internal": "\033[34m",
    "restricted": "\033[33m",
    "confidential": "\033[31m",
}
_RESET = "\033[0m"


def _c(text: str, colour: str) -> str:
    return f"{colour}{text}{_RESET}"


def format_sensitivity_match(sm: SensitivityMatch, *, colour: bool = True) -> str:
    tag = sm.sensitivity.upper()
    colour_code = _COLOURS.get(sm.sensitivity, "")
    tag_str = _c(f"[{tag}]", colour_code) if colour else f"[{tag}]"
    notes_str = f" — {sm.notes}" if sm.notes else ""
    return f"{tag_str} {sm.match.pattern_name} @ offset {sm.match.offset}{notes_str}"


def format_sensitivity_report(
    items: list[SensitivityMatch],
    *,
    colour: bool = True,
) -> str:
    if not items:
        return "No sensitivity-classified matches."
    lines = ["Sensitivity Report", "=================="]
    for sm in sorted(items, key=lambda x: -x.level):
        lines.append(format_sensitivity_match(sm, colour=colour))
    return "\n".join(lines)


def sensitivity_summary(items: list[SensitivityMatch]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for sm in items:
        summary[sm.sensitivity] = summary.get(sm.sensitivity, 0) + 1
    return summary
