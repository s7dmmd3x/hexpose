"""Match expiry: flag matches that have exceeded a maximum allowed age."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from hexpose.scanner import Match, ScanResult


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ExpiryMatch:
    match: Match
    first_seen: datetime
    max_age_days: int
    expires_at: datetime
    is_expired: bool

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "first_seen": self.first_seen.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "max_age_days": self.max_age_days,
            "is_expired": self.is_expired,
        }

    def __str__(self) -> str:
        state = "EXPIRED" if self.is_expired else "active"
        return (
            f"{self.match.pattern_name} [{state}] "
            f"expires={self.expires_at.date()}"
        )


def apply_expiry(
    match: Match,
    first_seen: datetime,
    max_age_days: int = 90,
    now: Optional[datetime] = None,
) -> ExpiryMatch:
    """Wrap *match* with expiry metadata."""
    if now is None:
        now = _utcnow()
    expires_at = first_seen + timedelta(days=max_age_days)
    is_expired = now >= expires_at
    return ExpiryMatch(
        match=match,
        first_seen=first_seen,
        max_age_days=max_age_days,
        expires_at=expires_at,
        is_expired=is_expired,
    )


def apply_expiry_all(
    result: ScanResult,
    first_seen: datetime,
    max_age_days: int = 90,
    now: Optional[datetime] = None,
) -> List[ExpiryMatch]:
    """Apply expiry to every match in *result*."""
    return [
        apply_expiry(m, first_seen, max_age_days, now)
        for m in result.matches
    ]
