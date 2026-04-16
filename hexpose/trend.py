"""Trend analysis across multiple scan timelines."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict
from hexpose.timeline import Timeline


@dataclass
class TrendPoint:
    label: str
    total_matches: int
    by_severity: Dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "total_matches": self.total_matches,
            "by_severity": self.by_severity,
        }


@dataclass
class TrendReport:
    points: List[TrendPoint] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"points": [p.as_dict() for p in self.points]}

    def __len__(self) -> int:
        return len(self.points)


def trend_point_from_timeline(timeline: Timeline, label: str) -> TrendPoint:
    """Aggregate a Timeline into a single TrendPoint."""
    total = 0
    by_severity: Dict[str, int] = {}
    for event in timeline._events:
        total += event.match_count
        for sev, cnt in event.severity_counts.items():
            by_severity[sev] = by_severity.get(sev, 0) + cnt
    return TrendPoint(label=label, total_matches=total, by_severity=by_severity)


def build_trend_report(timelines: List[Timeline], labels: List[str]) -> TrendReport:
    """Build a TrendReport from a list of timelines with corresponding labels."""
    if len(timelines) != len(labels):
        raise ValueError("timelines and labels must have equal length")
    points = [trend_point_from_timeline(t, l) for t, l in zip(timelines, labels)]
    return TrendReport(points=points)


def format_trend_report(report: TrendReport) -> str:
    if not report.points:
        return "No trend data."
    lines = ["Trend Report:", "-" * 40]
    for p in report.points:
        sev_str = ", ".join(f"{k}:{v}" for k, v in sorted(p.by_severity.items()))
        lines.append(f"  [{p.label}] total={p.total_matches}  {sev_str}")
    return "\n".join(lines)
