"""Formatting helpers for ThreatMatch results."""
from __future__ import annotations

from typing import List

from hexpose.match_threat import ThreatMatch

_ANSI = {
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}


def _c(text: str, colour: str) -> str:
    code = _ANSI.get(colour, "")
    return f"{code}{text}{_ANSI['reset']}" if code else text


def format_threat_match(tm: ThreatMatch) -> str:
    """Return a single-line human-readable string for *tm*."""
    level_colour = {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
    }.get(tm.threat_level, "cyan")

    level_tag = _c(f"[{tm.threat_level.upper()}]", level_colour)
    techs = ", ".join(tm.techniques) if tm.techniques else "none"
    return (
        f"{level_tag} {_c(tm.match.pattern_name, 'bold')} "
        f"tactic={tm.tactic} techniques={techs}"
    )


def format_threat_report(threat_matches: List[ThreatMatch]) -> str:
    """Return a multi-line report for a list of *ThreatMatch* objects."""
    if not threat_matches:
        return "No threat intelligence findings."
    lines = [_c("Threat Intelligence Report", "bold"), ""]
    for tm in threat_matches:
        lines.append(format_threat_match(tm))
    return "\n".join(lines)


def threat_summary(threat_matches: List[ThreatMatch]) -> str:
    """Return a one-line summary of threat findings."""
    if not threat_matches:
        return "threat: 0 findings"
    levels: dict[str, int] = {}
    for tm in threat_matches:
        levels[tm.threat_level] = levels.get(tm.threat_level, 0) + 1
    parts = [f"{lvl}={cnt}" for lvl, cnt in sorted(levels.items())]
    return f"threat: {len(threat_matches)} findings ({', '.join(parts)})"
