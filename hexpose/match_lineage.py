"""Track transformation lineage for matches — records which processing
steps a match has passed through."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from hexpose.scanner import Match, ScanResult


@dataclass
class LineageMatch:
    match: Match
    steps: List[str] = field(default_factory=list)

    def add(self, step: str) -> "LineageMatch":
        """Record a processing step and return self for chaining."""
        s = step.strip()
        if s:
            self.steps.append(s)
        return self

    def has_step(self, step: str) -> bool:
        return step in self.steps

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "severity": self.match.severity,
            "steps": list(self.steps),
        }

    def __str__(self) -> str:
        return f"{self.match.pattern_name} lineage=[{', '.join(self.steps)}]"


def track_lineage(match: Match, *steps: str) -> LineageMatch:
    """Wrap *match* in a LineageMatch and record initial *steps*."""
    lm = LineageMatch(match=match)
    for s in steps:
        lm.add(s)
    return lm


def track_lineage_all(
    result: ScanResult, *steps: str
) -> List[LineageMatch]:
    """Apply :func:`track_lineage` to every match in *result*."""
    return [track_lineage(m, *steps) for m in result.matches]
