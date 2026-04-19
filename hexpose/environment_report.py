"""Formatting helpers for EnvironmentMatch objects."""
from __future__ import annotations

from typing import List

from hexpose.match_environment import EnvironmentMatch

_RESET = "\033[0m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"
_YELLOW = "\033[33m"


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}"


def format_environment_match(em: EnvironmentMatch) -> str:
    env = _c(em.env_name, _CYAN)
    name = _c(em.match.pattern_name, _BOLD)
    sev = em.match.severity
    parts = [f"{env} | {name} | severity={sev}"]
    if em.region:
        parts.append(f"region={em.region}")
    if em.team:
        parts.append(f"team={_c(em.team, _YELLOW)}")
    if em.tags:
        parts.append("tags=" + ",".join(em.tags))
    return " | ".join(parts)


def format_environment_report(items: List[EnvironmentMatch]) -> str:
    if not items:
        return "No environment-annotated matches."
    lines = ["Environment Report", "=" * 40]
    for em in items:
        lines.append(format_environment_match(em))
    return "\n".join(lines)


def environment_summary(items: List[EnvironmentMatch]) -> str:
    if not items:
        return "0 environment-annotated matches."
    envs = {em.env_name for em in items}
    return (
        f"{len(items)} match(es) across "
        f"{len(envs)} environment(s): {', '.join(sorted(envs))}"
    )
