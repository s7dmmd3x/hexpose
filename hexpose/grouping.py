"""Group scan matches by various dimensions."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List
from hexpose.scanner import Match, ScanResult


@dataclass
class GroupedMatches:
    by: str
    groups: Dict[str, List[Match]] = field(default_factory=dict)

    def keys(self) -> List[str]:
        return list(self.groups.keys())

    def get(self, key: str) -> List[Match]:
        return self.groups.get(key, [])

    def as_dict(self) -> dict:
        return {
            "by": self.by,
            "groups": {k: [m.value for m in v] for k, v in self.groups.items()},
        }


def group_by_pattern(matches: List[Match]) -> GroupedMatches:
    groups: Dict[str, List[Match]] = {}
    for m in matches:
        groups.setdefault(m.pattern_name, []).append(m)
    return GroupedMatches(by="pattern", groups=groups)


def group_by_severity(matches: List[Match]) -> GroupedMatches:
    groups: Dict[str, List[Match]] = {}
    for m in matches:
        groups.setdefault(m.severity, []).append(m)
    return GroupedMatches(by="severity", groups=groups)


def group_by_offset_range(matches: List[Match], bucket_size: int = 512) -> GroupedMatches:
    groups: Dict[str, List[Match]] = {}
    for m in matches:
        bucket = (m.offset // bucket_size) * bucket_size
        key = f"{bucket}-{bucket + bucket_size - 1}"
        groups.setdefault(key, []).append(m)
    return GroupedMatches(by="offset_range", groups=groups)


def group_result(result: ScanResult, by: str = "pattern", **kwargs) -> GroupedMatches:
    if by == "pattern":
        return group_by_pattern(result.matches)
    if by == "severity":
        return group_by_severity(result.matches)
    if by == "offset_range":
        return group_by_offset_range(result.matches, **kwargs)
    raise ValueError(f"Unknown grouping dimension: {by!r}")
