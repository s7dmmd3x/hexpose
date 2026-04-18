"""Severity map: aggregate and remap severity levels across scan results."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from hexpose.scanner import Match, ScanResult
from hexpose.severity import Severity, parse_severity


@dataclass
class SeverityMapEntry:
    severity: str
    count: int
    pattern_names: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "count": self.count,
            "pattern_names": sorted(set(self.pattern_names)),
        }


@dataclass
class SeverityMap:
    entries: Dict[str, SeverityMapEntry] = field(default_factory=dict)

    def keys(self) -> List[str]:
        return list(self.entries.keys())

    def get(self, severity: str) -> SeverityMapEntry | None:
        return self.entries.get(severity.lower())

    def as_dict(self) -> dict:
        return {k: v.as_dict() for k, v in self.entries.items()}


def build_severity_map(matches: List[Match]) -> SeverityMap:
    """Build a SeverityMap from a flat list of Match objects."""
    entries: Dict[str, SeverityMapEntry] = {}
    for match in matches:
        key = (match.severity or "unknown").lower()
        if key not in entries:
            entries[key] = SeverityMapEntry(severity=key, count=0)
        entries[key].count += 1
        entries[key].pattern_names.append(match.pattern_name)
    return SeverityMap(entries=entries)


def build_severity_map_from_result(result: ScanResult) -> SeverityMap:
    return build_severity_map(result.matches)


def build_severity_map_from_results(results: List[ScanResult]) -> SeverityMap:
    """Merge severity maps across multiple ScanResult objects."""
    all_matches: List[Match] = []
    for r in results:
        all_matches.extend(r.matches)
    return build_severity_map(all_matches)


def remap_severity(matches: List[Match], remap: Dict[str, str]) -> List[Match]:
    """Return copies of matches with severity remapped according to the dict."""
    remapped = []
    for m in matches:
        key = (m.severity or "unknown").lower()
        new_severity = remap.get(key, m.severity)
        remapped.append(
            Match(
                pattern_name=m.pattern_name,
                value=m.value,
                offset=m.offset,
                severity=new_severity,
            )
        )
    return remapped
