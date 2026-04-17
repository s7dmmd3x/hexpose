"""chain_builtins.py — ready-made transform steps for MatchChain."""
from __future__ import annotations
from typing import Container, Optional
from hexpose.scanner import Match
from hexpose.entropy import shannon_entropy


def drop_low_entropy(min_entropy: float = 3.0):
    """Return a step that drops matches whose value has entropy below threshold."""
    def _step(match: Match) -> Optional[Match]:
        if shannon_entropy(match.value.encode()) < min_entropy:
            return None
        return match
    return _step


def drop_patterns(names: Container[str]):
    """Return a step that drops matches whose pattern name is in *names*."""
    def _step(match: Match) -> Optional[Match]:
        if match.pattern_name in names:
            return None
        return match
    return _step


def require_min_length(min_len: int = 8):
    """Return a step that drops matches shorter than *min_len* characters."""
    def _step(match: Match) -> Optional[Match]:
        if len(match.value) < min_len:
            return None
        return match
    return _step


def uppercase_value(match: Match) -> Match:
    """Transform step that upper-cases the matched value (example mutator)."""
    return Match(
        pattern_name=match.pattern_name,
        value=match.value.upper(),
        offset=match.offset,
        severity=match.severity,
    )
