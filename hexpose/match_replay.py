"""match_replay.py — replay recorded matches against updated patterns.

Allows users to re-evaluate previously captured matches against the current
pattern set to detect regressions, improvements, or newly relevant rules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from hexpose.scanner import Match, ScanResult
from hexpose.patterns import SecretPattern


@dataclass
class ReplayMatch:
    """A match decorated with replay comparison metadata."""

    original: Match
    replayed: bool          # True if the match was reproduced by current patterns
    pattern_changed: bool   # True if the matching pattern definition changed
    new_severity: Optional[str]  # Severity from current pattern (None if not replayed)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.original.pattern_name,
            "value": self.original.value,
            "offset": self.original.offset,
            "original_severity": self.original.severity,
            "replayed": self.replayed,
            "pattern_changed": self.pattern_changed,
            "new_severity": self.new_severity,
        }

    def __str__(self) -> str:
        status = "REPLAYED" if self.replayed else "DROPPED"
        change = " [severity changed]" if self.pattern_changed else ""
        return f"[{status}]{change} {self.original.pattern_name}: {self.original.value[:40]!r}"


@dataclass
class ReplayReport:
    """Aggregated results of replaying a set of matches."""

    replayed: List[ReplayMatch] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.replayed)

    @property
    def reproduced(self) -> List[ReplayMatch]:
        return [r for r in self.replayed if r.replayed]

    @property
    def dropped(self) -> List[ReplayMatch]:
        return [r for r in self.replayed if not r.replayed]

    @property
    def severity_changed(self) -> List[ReplayMatch]:
        return [r for r in self.replayed if r.pattern_changed]

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "reproduced": len(self.reproduced),
            "dropped": len(self.dropped),
            "severity_changed": len(self.severity_changed),
            "matches": [r.as_dict() for r in self.replayed],
        }


def _pattern_map(patterns: Sequence[SecretPattern]) -> dict[str, SecretPattern]:
    """Index patterns by name for fast lookup."""
    return {p.name: p for p in patterns}


def replay_match(match: Match, patterns: Sequence[SecretPattern]) -> ReplayMatch:
    """Replay a single *match* against *patterns*.

    A match is considered *replayed* when a pattern with the same name still
    exists **and** its regex still matches the original value.
    """
    pmap = _pattern_map(patterns)
    current = pmap.get(match.pattern_name)

    if current is None:
        # Pattern has been removed entirely.
        return ReplayMatch(
            original=match,
            replayed=False,
            pattern_changed=True,
            new_severity=None,
        )

    still_matches = bool(current.regex.search(match.value))
    severity_changed = current.severity != match.severity

    return ReplayMatch(
        original=match,
        replayed=still_matches,
        pattern_changed=severity_changed,
        new_severity=current.severity if still_matches else None,
    )


def replay_result(
    result: ScanResult, patterns: Sequence[SecretPattern]
) -> ReplayReport:
    """Replay all matches from a *ScanResult* against *patterns*."""
    report = ReplayReport()
    for match in result.matches:
        report.replayed.append(replay_match(match, patterns))
    return report


def replay_from_json(
    path: str | Path, patterns: Sequence[SecretPattern]
) -> ReplayReport:
    """Load a previously exported JSON result file and replay its matches.

    The JSON is expected to contain a list of match dicts as produced by
    ``hexpose.export.to_json``.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    report = ReplayReport()
    for entry in data:
        match = Match(
            pattern_name=entry["pattern_name"],
            value=entry["value"],
            offset=entry.get("offset", 0),
            severity=entry.get("severity", "unknown"),
        )
        report.replayed.append(replay_match(match, patterns))
    return report
