"""Match resolution — attach a resolution status and notes to a match."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from hexpose.scanner import Match, ScanResult


_VALID_RESOLUTIONS = {"open", "fixed", "wont_fix", "false_positive", "duplicate"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ResolutionMatch:
    match: Match
    resolution: str
    resolved_by: Optional[str]
    resolved_at: Optional[datetime]
    notes: List[str]

    def is_resolved(self) -> bool:
        return self.resolution != "open"

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "resolution": self.resolution,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "notes": list(self.notes),
        }

    def __str__(self) -> str:
        ts = self.resolved_at.isoformat() if self.resolved_at else "-"
        return (
            f"[{self.resolution.upper()}] {self.match.pattern_name} "
            f"by {self.resolved_by or 'unknown'} at {ts}"
        )


def resolve_match(
    match: Match,
    resolution: str = "open",
    resolved_by: Optional[str] = None,
    notes: Optional[List[str]] = None,
    timestamp: Optional[datetime] = None,
) -> ResolutionMatch:
    resolution = resolution.strip().lower()
    if resolution not in _VALID_RESOLUTIONS:
        raise ValueError(
            f"Invalid resolution {resolution!r}. "
            f"Must be one of: {sorted(_VALID_RESOLUTIONS)}"
        )
    resolved_at = (timestamp or _utcnow()) if resolution != "open" else None
    cleaned_notes = [n.strip() for n in (notes or []) if n.strip()]
    return ResolutionMatch(
        match=match,
        resolution=resolution,
        resolved_by=resolved_by.strip() if resolved_by else None,
        resolved_at=resolved_at,
        notes=cleaned_notes,
    )


def resolve_all(
    result: ScanResult,
    resolution: str = "open",
    resolved_by: Optional[str] = None,
    notes: Optional[List[str]] = None,
) -> List[ResolutionMatch]:
    return [
        resolve_match(m, resolution=resolution, resolved_by=resolved_by, notes=notes)
        for m in result.matches
    ]
