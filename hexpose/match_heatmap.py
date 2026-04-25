"""match_heatmap.py — builds a frequency heatmap of matches across offset ranges."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class HeatmapBucket:
    """A single bucket in the offset heatmap."""
    start: int
    end: int
    count: int = 0
    patterns: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "count": self.count,
            "patterns": sorted(set(self.patterns)),
        }


@dataclass
class MatchHeatmap:
    """Heatmap of match density across the scanned byte range."""
    bucket_size: int
    buckets: Dict[int, HeatmapBucket] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.buckets)

    def hotspots(self, top_n: int = 5) -> List[HeatmapBucket]:
        """Return top_n buckets sorted by descending count."""
        sorted_buckets = sorted(self.buckets.values(), key=lambda b: b.count, reverse=True)
        return sorted_buckets[:top_n]

    def as_dict(self) -> dict:
        return {
            "bucket_size": self.bucket_size,
            "buckets": [b.as_dict() for b in sorted(self.buckets.values(), key=lambda b: b.start)],
        }


def build_heatmap(
    results: List[ScanResult],
    bucket_size: int = 256,
) -> MatchHeatmap:
    """Build a heatmap from a list of ScanResult objects.

    Args:
        results: Scan results to aggregate.
        bucket_size: Size of each offset bucket in bytes.

    Returns:
        A MatchHeatmap instance.
    """
    if bucket_size < 1:
        raise ValueError("bucket_size must be >= 1")

    heatmap = MatchHeatmap(bucket_size=bucket_size)

    for result in results:
        for match in result.matches:
            bucket_index = match.offset // bucket_size
            if bucket_index not in heatmap.buckets:
                start = bucket_index * bucket_size
                heatmap.buckets[bucket_index] = HeatmapBucket(
                    start=start,
                    end=start + bucket_size - 1,
                )
            bucket = heatmap.buckets[bucket_index]
            bucket.count += 1
            bucket.patterns.append(match.pattern_name)

    return heatmap
