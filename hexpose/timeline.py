"""Timeline: track scan events and build a chronological audit trail."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from hexpose.scanner import ScanResult


@dataclass
class TimelineEvent:
    timestamp: datetime
    source: str
    total_matches: int
    pattern_names: List[str]
    metadata: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "total_matches": self.total_matches,
            "pattern_names": self.pattern_names,
            "metadata": self.metadata,
        }


@dataclass
class Timeline:
    events: List[TimelineEvent] = field(default_factory=list)

    def add_event(self, event: TimelineEvent) -> None:
        self.events.append(event)

    def __len__(self) -> int:
        return len(self.events)

    def latest(self) -> Optional[TimelineEvent]:
        return self.events[-1] if self.events else None

    def as_dict(self) -> dict:
        return {"events": [e.as_dict() for e in self.events]}


def event_from_result(
    result: ScanResult,
    metadata: Optional[dict] = None,
) -> TimelineEvent:
    """Build a TimelineEvent from a ScanResult."""
    pattern_names = list({m.pattern_name for m in result.matches})
    return TimelineEvent(
        timestamp=datetime.now(timezone.utc),
        source=result.source,
        total_matches=len(result.matches),
        pattern_names=sorted(pattern_names),
        metadata=metadata or {},
    )


def build_timeline(results: List[ScanResult], metadata: Optional[dict] = None) -> Timeline:
    """Build a Timeline from a list of ScanResults."""
    tl = Timeline()
    for r in results:
        tl.add_event(event_from_result(r, metadata))
    return tl


def format_timeline(timeline: Timeline) -> str:
    """Return a human-readable timeline string."""
    if not timeline.events:
        return "No timeline events."
    lines = ["Scan Timeline:", "-" * 40]
    for ev in timeline.events:
        match_str = f"{ev.total_matches} match(es)"
        patterns = ", ".join(ev.pattern_names) if ev.pattern_names else "none"
        lines.append(f"[{ev.timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')}] {ev.source} — {match_str} | patterns: {patterns}")
    return "\n".join(lines)
