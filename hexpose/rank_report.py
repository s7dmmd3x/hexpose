"""Formatting helpers for ranked match reports."""
from __future__ import annotations
from typing import List

from hexpose.match_rank import RankedMatch

try:
    from colorama import Fore, Style
    _COLOR = True
except ImportError:
    _COLOR = False


def _c(text: str, color: str) -> str:
    if not _COLOR:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def format_ranked_match(rm: RankedMatch, index: int = 0) -> str:
    rank_str = _c(f"#{index + 1}", Fore.CYAN if _COLOR else "")
    name = _c(rm.match.pattern_name, Fore.YELLOW if _COLOR else "")
    score = _c(f"{rm.rank_score:.3f}", Fore.GREEN if _COLOR else "")
    sev = rm.match.severity if isinstance(rm.match.severity, str) else str(rm.match.severity)
    return (
        f"{rank_str} [{score}] {name} "
        f"| severity={sev} entropy={rm.entropy_score:.3f} "
        f"| value={rm.match.value[:40]!r}"
    )


def format_rank_report(ranked: List[RankedMatch]) -> str:
    if not ranked:
        return "No matches to rank."
    lines = [_c("=== Match Ranking Report ===", Fore.MAGENTA if _COLOR else "")]
    for i, rm in enumerate(ranked):
        lines.append(format_ranked_match(rm, i))
    return "\n".join(lines)


def rank_summary(ranked: List[RankedMatch]) -> str:
    if not ranked:
        return "Ranked 0 matches."
    top = ranked[0]
    return (
        f"Ranked {len(ranked)} match(es). "
        f"Top: {top.match.pattern_name} (score={top.rank_score:.3f})"
    )
