"""match_audit.py — audit trail for match lifecycle events."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from hexpose.scanner import Match


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AuditEvent:
    action: str
    actor: str
    timestamp: datetime
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "action": self.action,
            "actor": self.actor,
            "timestamp": self.timestamp.isoformat(),
            "notes": self.notes,
        }


@dataclass
class AuditedMatch:
    match: Match
    events: List[AuditEvent] = field(default_factory=list)

    def add(self, action: str, actor: str, notes: str = "") -> "AuditedMatch":
        self.events.append(
            AuditEvent(action=action.strip(), actor=actor.strip(), timestamp=_utcnow(), notes=notes.strip())
        )
        return self

    def last_event(self) -> Optional[AuditEvent]:
        return self.events[-1] if self.events else None

    def has_action(self, action: str) -> bool:
        return any(e.action == action for e in self.events)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "severity": self.match.severity,
            "events": [e.as_dict() for e in self.events],
        }

    def __str__(self) -> str:
        return f"AuditedMatch({self.match.pattern_name}, events={len(self.events)})"


def audit_match(
    match: Match,
    action: str,
    actor: str,
    notes: str = "",
) -> AuditedMatch:
    """Wrap *match* in an AuditedMatch and record the first event."""
    am = AuditedMatch(match=match)
    am.add(action=action, actor=actor, notes=notes)
    return am


def audit_all(
    matches: List[Match],
    action: str,
    actor: str,
    notes: str = "",
) -> List[AuditedMatch]:
    """Apply audit_match to every match in *matches*."""
    return [audit_match(m, action=action, actor=actor, notes=notes) for m in matches]
