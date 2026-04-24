"""match_recurrence.py – track how often a match recurs across multiple scans."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class RecurringMatch:
    """Wraps a Match with recurrence metadata."""

    match: Match
    seen_count: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    scan_ids: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "seen_count": self.seen_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "scan_ids": list(self.scan_ids),
        }

    def __str__(self) -> str:  # pragma: no cover
        return (
            f"{self.match.pattern_name} seen {self.seen_count}x "
            f"(first={self.first_seen}, last={self.last_seen})"
        )


def _match_key(m: Match) -> str:
    """Stable key that identifies a logical match independent of scan."""
    return f"{m.pattern_name}::{m.value}"


def build_recurrence(
    results: List[ScanResult],
    scan_ids: Optional[List[str]] = None,
) -> List[RecurringMatch]:
    """Aggregate matches from multiple ScanResults into RecurringMatch objects.

    Parameters
    ----------
    results:
        Ordered list of ScanResult objects (oldest first).
    scan_ids:
        Optional parallel list of scan identifiers.  Falls back to
        ``str(index)`` when not supplied.
    """
    if scan_ids is None:
        scan_ids = [str(i) for i in range(len(results))]

    if len(scan_ids) != len(results):
        raise ValueError("scan_ids length must match results length")

    # key -> {first_seen, last_seen, count, scan_ids, match}
    registry: dict = {}

    for scan_id, result in zip(scan_ids, results):
        for match in result.matches:
            key = _match_key(match)
            if key not in registry:
                registry[key] = {
                    "match": match,
                    "first_seen": scan_id,
                    "last_seen": scan_id,
                    "count": 0,
                    "scan_ids": [],
                }
            entry = registry[key]
            entry["count"] += 1
            entry["last_seen"] = scan_id
            entry["scan_ids"].append(scan_id)

    return [
        RecurringMatch(
            match=entry["match"],
            seen_count=entry["count"],
            first_seen=entry["first_seen"],
            last_seen=entry["last_seen"],
            scan_ids=entry["scan_ids"],
        )
        for entry in registry.values()
    ]


def top_recurring(recurring: List[RecurringMatch], n: int = 10) -> List[RecurringMatch]:
    """Return the *n* most frequently recurring matches."""
    return sorted(recurring, key=lambda r: r.seen_count, reverse=True)[:n]
