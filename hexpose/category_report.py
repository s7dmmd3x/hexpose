"""Formatting helpers for categorised match output."""
from __future__ import annotations
from typing import List
from hexpose.match_category import CategorisedMatch, group_by_category
from hexpose.scanner import Match

try:
    from colorama import Fore, Style
    _COLOUR = True
except ImportError:
    _COLOUR = False

_CATEGORY_COLOURS = {
    "cloud": "\033[94m",
    "vcs": "\033[96m",
    "auth_token": "\033[93m",
    "credential": "\033[91m",
    "api_key": "\033[95m",
    "cryptographic": "\033[92m",
    "unknown": "\033[90m",
}
_RESET = "\033[0m"


def _c(text: str, colour: str) -> str:
    return f"{colour}{text}{_RESET}"


def format_categorised_match(cm: CategorisedMatch, *, colour: bool = False) -> str:
    cat = cm.category
    col = _CATEGORY_COLOURS.get(cat, "")
    cat_str = _c(f"[{cat}]", col) if colour else f"[{cat}]"
    return f"{cat_str} {cm.match.pattern_name} @ offset {cm.match.offset}: {cm.match.value}"


def format_category_report(cms: List[CategorisedMatch], *, colour: bool = False) -> str:
    if not cms:
        return "No categorised matches."
    lines = [format_categorised_match(cm, colour=colour) for cm in cms]
    return "\n".join(lines)


def category_summary(matches: List[Match]) -> str:
    groups = group_by_category(matches)
    if not groups:
        return "No matches to categorise."
    lines = ["Category summary:"]
    for cat, ms in sorted(groups.items()):
        lines.append(f"  {cat}: {len(ms)} match(es)")
    return "\n".join(lines)
