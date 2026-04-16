"""Deduplication of scan matches based on configurable strategies."""

from __future__ import annotations

from enum import Enum
from typing import List

from hexpose.scanner import Match, ScanResult


class DedupStrategy(str, Enum):
    """Strategy used to identify duplicate matches."""

    EXACT = "exact"          # same offset + pattern + value
    VALUE = "value"          # same pattern + value (ignore offset)
    FINGERPRINT = "fingerprint"  # same fingerprint (hash-based)


def _key_exact(match: Match) -> tuple:
    return (match.pattern_name, match.offset, match.value)


def _key_value(match: Match) -> tuple:
    return (match.pattern_name, match.value)


def _key_fingerprint(match: Match) -> str:
    import hashlib
    raw = f"{match.pattern_name}:{match.value}"
    return hashlib.sha256(raw.encode()).hexdigest()


_STRATEGY_MAP = {
    DedupStrategy.EXACT: _key_exact,
    DedupStrategy.VALUE: _key_value,
    DedupStrategy.FINGERPRINT: _key_fingerprint,
}


def dedup_matches(
    matches: List[Match],
    strategy: DedupStrategy = DedupStrategy.VALUE,
) -> List[Match]:
    """Return a deduplicated list of matches preserving first-seen order."""
    key_fn = _STRATEGY_MAP[strategy]
    seen: set = set()
    result: List[Match] = []
    for match in matches:
        key = key_fn(match)
        if key not in seen:
            seen.add(key)
            result.append(match)
    return result


def dedup_result(
    result: ScanResult,
    strategy: DedupStrategy = DedupStrategy.VALUE,
) -> ScanResult:
    """Return a new ScanResult with deduplicated matches."""
    deduped = dedup_matches(result.matches, strategy=strategy)
    return ScanResult(
        source=result.source,
        matches=deduped,
        metadata=dict(result.metadata),
    )
