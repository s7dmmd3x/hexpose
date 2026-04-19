"""Attach ownership metadata (owner, team, contact) to a match."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class OwnershipMatch:
    match: Match
    owner: str
    team: str
    contact: str
    tags: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "severity": self.match.severity,
            "owner": self.owner,
            "team": self.team,
            "contact": self.contact,
            "tags": list(self.tags),
        }

    def __str__(self) -> str:
        return (
            f"[{self.match.severity}] {self.match.pattern_name} "
            f"owner={self.owner} team={self.team}"
        )


def attach_ownership(
    match: Match,
    owner: str = "unknown",
    team: str = "unknown",
    contact: str = "",
    tags: Optional[List[str]] = None,
) -> OwnershipMatch:
    """Wrap *match* with ownership information."""
    return OwnershipMatch(
        match=match,
        owner=owner.strip() or "unknown",
        team=team.strip() or "unknown",
        contact=contact.strip(),
        tags=[t.strip() for t in (tags or []) if t.strip()],
    )


def attach_ownership_all(
    result: ScanResult,
    owner: str = "unknown",
    team: str = "unknown",
    contact: str = "",
    tags: Optional[List[str]] = None,
) -> List[OwnershipMatch]:
    """Apply :func:`attach_ownership` to every match in *result*."""
    return [
        attach_ownership(m, owner=owner, team=team, contact=contact, tags=tags)
        for m in result.matches
    ]
