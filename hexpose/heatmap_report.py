"""heatmap_report.py — text formatting for MatchHeatmap."""
from __future__ import annotations

from typing import List

from hexpose.match_heatmap import HeatmapBucket, MatchHeatmap

_BAR_WIDTH = 20


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def _bar(count: int, max_count: int) -> str:
    if max_count == 0:
        return ""
    filled = round((count / max_count) * _BAR_WIDTH)
    return "█" * filled + "░" * (_BAR_WIDTH - filled)


def format_bucket(bucket: HeatmapBucket, max_count: int) -> str:
    """Format a single heatmap bucket as a text row."""
    bar = _bar(bucket.count, max_count)
    patterns = ", ".join(sorted(set(bucket.patterns))) or "—"
    offset_range = _c(f"0x{bucket.start:08x}-0x{bucket.end:08x}", "36")
    count_str = _c(str(bucket.count).rjust(4), "33")
    return f"  {offset_range}  {bar}  {count_str}  {patterns}"


def format_heatmap_report(heatmap: MatchHeatmap) -> str:
    """Return a full text report for a MatchHeatmap."""
    if not heatmap.buckets:
        return _c("No matches recorded in heatmap.", "90")

    lines: List[str] = [
        _c(f"Match Heatmap  (bucket size: {heatmap.bucket_size} bytes)", "1;34"),
        "",
    ]
    sorted_buckets = sorted(heatmap.buckets.values(), key=lambda b: b.start)
    max_count = max(b.count for b in sorted_buckets)
    for bucket in sorted_buckets:
        lines.append(format_bucket(bucket, max_count))

    lines.append("")
    lines.append(_c(f"Total buckets: {len(heatmap.buckets)}", "90"))
    return "\n".join(lines)


def heatmap_summary(heatmap: MatchHeatmap, top_n: int = 3) -> str:
    """Return a short summary highlighting the hottest buckets."""
    hotspots = heatmap.hotspots(top_n=top_n)
    if not hotspots:
        return "Heatmap: no data."
    parts = [
        f"0x{b.start:08x}({b.count})"
        for b in hotspots
    ]
    return _c("Hotspots: ", "1") + ", ".join(parts)
