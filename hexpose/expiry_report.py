"""Formatting helpers for ExpiryMatch results."""
from __future__ import annotations

from typing import List

from hexpose.match_expiry import ExpiryMatch

_RED = "\033[31m"
_GREEN = "\033[32m"
_RESET = "\033[0m"


def _c(text: str, colour: str) -> str:
    return f"{colour}{text}{_RESET}"


def format_expiry_match(em: ExpiryMatch) -> str:
    state = _c("EXPIRED", _RED) if em.is_expired else _c("active", _GREEN)
    return (
        f"[{state}] {em.match.pattern_name} | "
        f"first_seen={em.first_seen.date()} "
        f"expires={em.expires_at.date()} "
        f"(max {em.max_age_days}d)"
    )


def format_expiry_report(expiry_matches: List[ExpiryMatch]) -> str:
    if not expiry_matches:
        return "No matches to report."
    lines = ["=== Expiry Report ==="]
    for em in expiry_matches:
        lines.append(format_expiry_match(em))
    return "\n".join(lines)


def expiry_summary(expiry_matches: List[ExpiryMatch]) -> str:
    total = len(expiry_matches)
    expired = sum(1 for em in expiry_matches if em.is_expired)
    active = total - expired
    return (
        f"Expiry summary: {total} total, "
        f"{_c(str(expired), _RED)} expired, "
        f"{_c(str(active), _GREEN)} active"
    )
