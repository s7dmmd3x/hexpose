"""Correlate matches across multiple scan results by shared value or pattern."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class CorrelationGroup:
    key: str
    matches: List[Match] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    def add(self, match: Match, source: str = "") -> None:
        self.matches.append(match)
        if source and source not in self.sources:
            self.sources.append(source)

    @property
    def size(self) -> int:
        return len(self.matches)

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "match_count": self.size,
            "sources": self.sources,
            "pattern_names": list({m.pattern_name for m in self.matches}),
        }


def correlate_by_value(
    results: List[ScanResult],
    source_labels: Optional[List[str]] = None,
) -> Dict[str, CorrelationGroup]:
    """Group matches from multiple results that share the same matched value."""
    labels = source_labels or [""] * len(results)
    groups: Dict[str, CorrelationGroup] = {}
    for result, label in zip(results, labels):
        for match in result.matches:
            key = match.value
            if key not in groups:
                groups[key] = CorrelationGroup(key=key)
            groups[key].add(match, label)
    return {k: v for k, v in groups.items() if v.size > 1}


def correlate_by_pattern(
    results: List[ScanResult],
    source_labels: Optional[List[str]] = None,
) -> Dict[str, CorrelationGroup]:
    """Group matches from multiple results that share the same pattern name."""
    labels = source_labels or [""] * len(results)
    groups: Dict[str, CorrelationGroup] = {}
    for result, label in zip(results, labels):
        for match in result.matches:
            key = match.pattern_name
            if key not in groups:
                groups[key] = CorrelationGroup(key=key)
            groups[key].add(match, label)
    return groups
