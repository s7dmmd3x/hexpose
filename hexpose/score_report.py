"""Formatted reporting for scored matches."""
from typing import List
from hexpose.scoring import ScoredMatch

_GRADE_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[34m",
    "INFO":     "\033[37m",
}
_RESET = "\033[0m"


def _colorize(grade: str, text: str, color: bool) -> str:
    if not color:
        return text
    return f"{_GRADE_COLORS.get(grade, '')}{text}{_RESET}"


def format_scored_match(sm: ScoredMatch, color: bool = True) -> str:
    match = sm.match
    name = getattr(match, "pattern_name", "unknown")
    value = getattr(match, "value", "")
    grade_str = _colorize(sm.grade, sm.grade, color)
    return (
        f"[{grade_str}] {name} | score={sm.final_score} "
        f"(base={sm.base_score} entropy+={sm.entropy_bonus} "
        f"watchlist+={sm.watchlist_bonus}) | {value!r}"
    )


def format_score_report(scored: List[ScoredMatch], color: bool = True) -> str:
    if not scored:
        return "No scored matches."
    lines = [f"Scored matches ({len(scored)}):", ""]
    for sm in sorted(scored, key=lambda s: s.final_score, reverse=True):
        lines.append(format_scored_match(sm, color=color))
    return "\n".join(lines)


def score_summary(scored: List[ScoredMatch]) -> dict:
    """Return grade distribution counts."""
    dist: dict = {}
    for sm in scored:
        dist[sm.grade] = dist.get(sm.grade, 0) + 1
    return dist
