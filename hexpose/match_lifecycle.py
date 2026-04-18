"""Match lifecycle tracking: created, updated, resolved timestamps."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from hexpose.scanner import Match


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class LifecycleMatch:
    match: Match
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    state: str  # "open" | "updated" | "resolved"

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "state": self.state,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


def open_match(
    match: Match,
    *,
    now: Optional[datetime] = None,
) -> LifecycleMatch:
    ts = now or _utcnow()
    return LifecycleMatch(match=match, created_at=ts, updated_at=ts, resolved_at=None, state="open")


def resolve_match(
    lm: LifecycleMatch,
    *,
    now: Optional[datetime] = None,
) -> LifecycleMatch:
    ts = now or _utcnow()
    return LifecycleMatch(
        match=lm.match,
        created_at=lm.created_at,
        updated_at=ts,
        resolved_at=ts,
        state="resolved",
    )


def update_match(
    lm: LifecycleMatch,
    new_match: Match,
    *,
    now: Optional[datetime] = None,
) -> LifecycleMatch:
    ts = now or _utcnow()
    return LifecycleMatch(
        match=new_match,
        created_at=lm.created_at,
        updated_at=ts,
        resolved_at=None,
        state="updated",
    )


def lifecycle_all(matches: list[Match], *, now: Optional[datetime] = None) -> list[LifecycleMatch]:
    return [open_match(m, now=now) for m in matches]
