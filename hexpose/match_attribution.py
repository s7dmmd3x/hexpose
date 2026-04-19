"""Attach attribution metadata (author, team, source system) to a match."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List

from hexpose.scanner import Match, ScanResult


@dataclass
class AttributedMatch:
    match: Match
    author: str
    team: str
    source_system: str
    tags: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "author": self.author,
            "team": self.team,
            "source_system": self.source_system,
            "tags": list(self.tags),
        }

    def __str__(self) -> str:
        return (
            f"[{self.match.severity}] {self.match.pattern_name} "
            f"| author={self.author} team={self.team} system={self.source_system}"
        )


def attribute_match(
    match: Match,
    author: str = "unknown",
    team: str = "unknown",
    source_system: str = "hexpose",
    tags: Optional[List[str]] = None,
) -> AttributedMatch:
    """Attach attribution metadata to a single match."""
    return AttributedMatch(
        match=match,
        author=author.strip() or "unknown",
        team=team.strip() or "unknown",
        source_system=source_system.strip() or "hexpose",
        tags=[t.strip().lower() for t in (tags or []) if t.strip()],
    )


def attribute_all(
    result: ScanResult,
    author: str = "unknown",
    team: str = "unknown",
    source_system: str = "hexpose",
    tags: Optional[List[str]] = None,
) -> List[AttributedMatch]:
    """Attribute every match in a ScanResult."""
    return [
        attribute_match(m, author=author, team=team,
                        source_system=source_system, tags=tags)
        for m in result.matches
    ]
