"""match_age.py – attach age/staleness metadata to matches based on a baseline timestamp."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class AgedMatch:
    match: Match
    first_seen: Optional[datetime]
    last_seen: datetime
    age_days: Optional[float]
    is_new: bool

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat(),
            "age_days": round(self.age_days, 2) if self.age_days is not None else None,
            "is_new": self.is_new,
        }


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def age_match(
    match: Match,
    baseline_timestamps: dict[str, datetime],
    now: Optional[datetime] = None,
) -> AgedMatch:
    """Return an AgedMatch for *match*.

    *baseline_timestamps* maps a match fingerprint (str) to the datetime it was
    first observed.  If the fingerprint is absent the match is considered new.
    """
    if now is None:
        now = _utcnow()

    key = f"{match.pattern_name}:{match.offset}:{match.value}"
    first_seen = baseline_timestamps.get(key)
    is_new = first_seen is None
    age_days = (now - first_seen).total_seconds() / 86400 if first_seen else None

    return AgedMatch(
        match=match,
        first_seen=first_seen,
        last_seen=now,
        age_days=age_days,
        is_new=is_new,
    )


def age_result(
    result: ScanResult,
    baseline_timestamps: dict[str, datetime],
    now: Optional[datetime] = None,
) -> list[AgedMatch]:
    """Apply age_match to every match in *result*."""
    if now is None:
        now = _utcnow()
    return [age_match(m, baseline_timestamps, now=now) for m in result.matches]
