"""risk_report: formatting helpers for RiskMatch results."""
from __future__ import annotations
from typing import List
from hexpose.match_risk import RiskMatch

_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[96m",
    "info": "\033[37m",
}
_RESET = "\033[0m"


def _c(level: str, text: str) -> str:
    return f"{_COLORS.get(level, '')}{text}{_RESET}"


def format_risk_match(rm: RiskMatch) -> str:
    level_str = _c(rm.risk_level, rm.risk_level.upper())
    score_str = f"{rm.risk_score:.3f}"
    return (
        f"[{level_str}] {rm.match.pattern_name} "
        f"score={score_str} offset={rm.match.offset} "
        f"value={rm.match.value!r}"
    )


def format_risk_report(risk_matches: List[RiskMatch]) -> str:
    if not risk_matches:
        return "No risk matches."
    lines = ["=== Risk Report ==="]
    for rm in sorted(risk_matches, key=lambda r: r.risk_score, reverse=True):
        lines.append(format_risk_match(rm))
    return "\n".join(lines)


def risk_summary(risk_matches: List[RiskMatch]) -> str:
    if not risk_matches:
        return "Risk summary: 0 matches."
    counts: dict = {}
    for rm in risk_matches:
        counts[rm.risk_level] = counts.get(rm.risk_level, 0) + 1
    parts = ", ".join(f"{_c(lvl, lvl)}={n}" for lvl, n in sorted(counts.items()))
    return f"Risk summary: {len(risk_matches)} matches — {parts}"
