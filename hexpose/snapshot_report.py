"""snapshot_report: human-readable formatting for match snapshots."""
from __future__ import annotations

from typing import List

from hexpose.match_snapshot import Snapshot, SnapshotEntry


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_entry(entry: SnapshotEntry) -> str:
    sev = entry.severity.upper()
    colour = {"CRITICAL": "31", "HIGH": "33", "MEDIUM": "34", "LOW": "32"}.get(sev, "37")
    return (
        f"  [{_c(sev, colour)}] {entry.pattern_name} "
        f"@ offset {entry.offset}: {entry.value[:40]}"
    )


def format_snapshot_report(snapshot: Snapshot) -> str:
    lines: List[str] = [
        _c(f"Snapshot taken at {snapshot.taken_at.isoformat()}", "1"),
        f"  Total entries: {len(snapshot.entries)}",
    ]
    for entry in snapshot.entries:
        lines.append(format_entry(entry))
    return "\n".join(lines)


def format_diff_report(
    added: List[SnapshotEntry],
    removed: List[SnapshotEntry],
) -> str:
    lines: List[str] = [_c("Snapshot Diff", "1")]
    if not added and not removed:
        lines.append("  No changes detected.")
        return "\n".join(lines)
    if added:
        lines.append(_c(f"  + {len(added)} new finding(s):", "32"))
        for e in added:
            lines.append("  + " + format_entry(e).strip())
    if removed:
        lines.append(_c(f"  - {len(removed)} resolved finding(s):", "31"))
        for e in removed:
            lines.append("  - " + format_entry(e).strip())
    return "\n".join(lines)


def snapshot_summary(snapshot: Snapshot) -> str:
    n = len(snapshot.entries)
    return f"Snapshot @ {snapshot.taken_at.isoformat()}: {n} finding(s)"
