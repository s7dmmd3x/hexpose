"""Cluster matches by proximity or shared attributes."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict
from hexpose.scanner import Match


@dataclass
class MatchCluster:
    key: str
    matches: List[Match] = field(default_factory=list)

    def add(self, match: Match) -> None:
        self.matches.append(match)

    def size(self) -> int:
        return len(self.matches)

    def as_dict(self) -> Dict:
        return {
            "key": self.key,
            "count": self.size(),
            "matches": [
                {
                    "pattern_name": m.pattern_name,
                    "value": m.value,
                    "offset": m.offset,
                    "severity": m.severity,
                }
                for m in self.matches
            ],
        }


def cluster_by_pattern(matches: List[Match]) -> Dict[str, MatchCluster]:
    """Group matches into clusters keyed by pattern name."""
    clusters: Dict[str, MatchCluster] = {}
    for m in matches:
        key = m.pattern_name
        if key not in clusters:
            clusters[key] = MatchCluster(key=key)
        clusters[key].add(m)
    return clusters


def cluster_by_proximity(matches: List[Match], window: int = 256) -> List[MatchCluster]:
    """Group matches that fall within *window* bytes of each other."""
    if not matches:
        return []
    sorted_matches = sorted(matches, key=lambda m: m.offset)
    clusters: List[MatchCluster] = []
    current = MatchCluster(key=f"proximity_{sorted_matches[0].offset}")
    current.add(sorted_matches[0])
    for m in sorted_matches[1:]:
        last_offset = current.matches[-1].offset
        if m.offset - last_offset <= window:
            current.add(m)
        else:
            clusters.append(current)
            current = MatchCluster(key=f"proximity_{m.offset}")
            current.add(m)
    clusters.append(current)
    return clusters


def largest_cluster(clusters: Dict[str, MatchCluster]) -> MatchCluster | None:
    if not clusters:
        return None
    return max(clusters.values(), key=lambda c: c.size())
