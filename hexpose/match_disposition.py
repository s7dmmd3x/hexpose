"""Match disposition — record analyst decisions (accept / reject / escalate)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from hexpose.scanner import Match


class Disposition:
    ACCEPT = "accept"
    REJECT = "reject"
    ESCALATE = "escalate"
    PENDING = "pending"

    _valid = {ACCEPT, REJECT, ESCALATE, PENDING}

    @classmethod
    def validate(cls, value: str) -> str:
        v = value.lower().strip()
        if v not in cls._valid:
            raise ValueError(f"Invalid disposition {value!r}; choose from {cls._valid}")
        return v


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class DispositionMatch:
    match: Match
    disposition: str
    analyst: str
    note: str
    decided_at: datetime

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "disposition": self.disposition,
            "analyst": self.analyst,
            "note": self.note,
            "decided_at": self.decided_at.isoformat(),
        }

    def __str__(self) -> str:
        return (
            f"[{self.disposition.upper()}] {self.match.pattern_name} "
            f"by {self.analyst or 'unknown'}"
        )


def dispose_match(
    match: Match,
    disposition: str,
    analyst: str = "",
    note: str = "",
    decided_at: Optional[datetime] = None,
) -> DispositionMatch:
    """Attach an analyst disposition to a match."""
    return DispositionMatch(
        match=match,
        disposition=Disposition.validate(disposition),
        analyst=analyst.strip(),
        note=note.strip(),
        decided_at=decided_at or _utcnow(),
    )


def dispose_all(
    matches: list[Match],
    disposition: str,
    analyst: str = "",
    note: str = "",
) -> list[DispositionMatch]:
    """Apply the same disposition to every match in a list."""
    return [dispose_match(m, disposition, analyst, note) for m in matches]
