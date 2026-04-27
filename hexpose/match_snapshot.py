"""match_snapshot: capture and compare point-in-time snapshots of scan results."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

from hexpose.scanner import Match, ScanResult


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class SnapshotEntry:
    pattern_name: str
    value: str
    offset: int
    severity: str

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.pattern_name,
            "value": self.value,
            "offset": self.offset,
            "severity": self.severity,
        }

    @staticmethod
    def from_match(m: Match) -> "SnapshotEntry":
        return SnapshotEntry(
            pattern_name=m.pattern_name,
            value=m.value,
            offset=m.offset,
            severity=m.severity,
        )

    @staticmethod
    def from_dict(d: dict) -> "SnapshotEntry":
        return SnapshotEntry(
            pattern_name=d["pattern_name"],
            value=d["value"],
            offset=d["offset"],
            severity=d["severity"],
        )


@dataclass
class Snapshot:
    taken_at: datetime
    entries: List[SnapshotEntry] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "taken_at": self.taken_at.isoformat(),
            "entries": [e.as_dict() for e in self.entries],
        }

    @staticmethod
    def from_dict(d: dict) -> "Snapshot":
        return Snapshot(
            taken_at=datetime.fromisoformat(d["taken_at"]),
            entries=[SnapshotEntry.from_dict(e) for e in d.get("entries", [])],
        )


def take_snapshot(results: Iterable[ScanResult]) -> Snapshot:
    """Build a Snapshot from an iterable of ScanResult objects."""
    entries: List[SnapshotEntry] = []
    for result in results:
        for match in result.matches:
            entries.append(SnapshotEntry.from_match(match))
    return Snapshot(taken_at=_utcnow(), entries=entries)


def save_snapshot(snapshot: Snapshot, path: Path) -> None:
    """Persist a snapshot to a JSON file."""
    path = Path(path)
    path.write_text(json.dumps(snapshot.as_dict(), indent=2), encoding="utf-8")


def load_snapshot(path: Path) -> Optional[Snapshot]:
    """Load a snapshot from a JSON file; returns None if file is missing."""
    path = Path(path)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return Snapshot.from_dict(data)


def diff_snapshots(
    old: Snapshot, new: Snapshot
) -> tuple[List[SnapshotEntry], List[SnapshotEntry]]:
    """Return (added, removed) entries between two snapshots."""
    def _key(e: SnapshotEntry) -> tuple:
        return (e.pattern_name, e.value, e.offset)

    old_keys = {_key(e): e for e in old.entries}
    new_keys = {_key(e): e for e in new.entries}
    added = [new_keys[k] for k in new_keys if k not in old_keys]
    removed = [old_keys[k] for k in old_keys if k not in new_keys]
    return added, removed
