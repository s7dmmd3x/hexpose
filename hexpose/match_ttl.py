"""match_ttl: time-to-live expiry tracking for matches."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from hexpose.scanner import Match, ScanResult


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class TTLMatch:
    match: Match
    expires_at: datetime
    expired: bool

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "expires_at": self.expires_at.isoformat(),
            "expired": self.expired,
        }

    def __str__(self) -> str:
        state = "EXPIRED" if self.expired else "ACTIVE"
        return f"[{state}] {self.match.pattern_name} expires={self.expires_at.isoformat()}"


def apply_ttl(
    match: Match,
    ttl_days: int = 30,
    *,
    reference: Optional[datetime] = None,
) -> TTLMatch:
    """Attach a TTL to *match* and evaluate whether it has expired.

    Parameters
    ----------
    match:
        The raw scanner match.
    ttl_days:
        Number of days before the match is considered expired.
    reference:
        Point in time to compare against; defaults to *now* (UTC).
    """
    now = reference or _utcnow()
    # Use the match's first_seen timestamp when available, otherwise now.
    first_seen: datetime = getattr(match, "first_seen", now)
    if first_seen.tzinfo is None:
        first_seen = first_seen.replace(tzinfo=timezone.utc)
    expires_at = first_seen + timedelta(days=ttl_days)
    expired = now >= expires_at
    return TTLMatch(match=match, expires_at=expires_at, expired=expired)


def apply_ttl_all(
    matches: Iterable[Match],
    ttl_days: int = 30,
    *,
    reference: Optional[datetime] = None,
) -> list[TTLMatch]:
    """Apply TTL to every match in *matches*."""
    return [apply_ttl(m, ttl_days, reference=reference) for m in matches]


def active_matches(ttl_matches: Iterable[TTLMatch]) -> list[TTLMatch]:
    """Return only non-expired TTL matches."""
    return [t for t in ttl_matches if not t.expired]


def expired_matches(ttl_matches: Iterable[TTLMatch]) -> list[TTLMatch]:
    """Return only expired TTL matches."""
    return [t for t in ttl_matches if t.expired]
