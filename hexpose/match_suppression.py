"""Per-match suppression with reason tracking."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from hexpose.scanner import Match


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class SuppressedMatch:
    match: Match
    suppressed: bool
    reason: str
    suppressed_by: str
    suppressed_at: Optional[datetime]

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "suppressed": self.suppressed,
            "reason": self.reason,
            "suppressed_by": self.suppressed_by,
            "suppressed_at": self.suppressed_at.isoformat() if self.suppressed_at else None,
        }

    def __str__(self) -> str:
        state = "suppressed" if self.suppressed else "active"
        return f"[{state}] {self.match.pattern_name} — {self.reason}"


def suppress_match(
    match: Match,
    reason: str = "",
    suppressed_by: str = "unknown",
    *,
    suppress: bool = True,
) -> SuppressedMatch:
    """Wrap a Match with suppression metadata."""
    reason = reason.strip()
    suppressed_by = suppressed_by.strip() or "unknown"
    return SuppressedMatch(
        match=match,
        suppressed=suppress,
        reason=reason,
        suppressed_by=suppressed_by,
        suppressed_at=_utcnow() if suppress else None,
    )


def suppress_all(
    matches: Iterable[Match],
    reason: str = "",
    suppressed_by: str = "unknown",
    *,
    suppress: bool = True,
) -> List[SuppressedMatch]:
    """Apply suppression to every match in *matches*."""
    return [
        suppress_match(m, reason=reason, suppressed_by=suppressed_by, suppress=suppress)
        for m in matches
    ]


def active_only(items: Iterable[SuppressedMatch]) -> List[SuppressedMatch]:
    """Return only non-suppressed items."""
    return [i for i in items if not i.suppressed]
