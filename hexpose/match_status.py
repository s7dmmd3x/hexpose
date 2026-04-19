"""Match status tracking — mark matches as new, confirmed, false-positive, etc."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List

from hexpose.scanner import Match, ScanResult


class Status(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"
    FIXED = "fixed"


@dataclass
class StatusedMatch:
    match: Match
    status: Status = Status.NEW
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "status": self.status.value,
            "note": self.note,
        }

    def __str__(self) -> str:
        return f"[{self.status.value.upper()}] {self.match.pattern_name} @ {self.match.offset}"


def set_status(
    match: Match,
    status: Status,
    note: str = "",
) -> StatusedMatch:
    """Wrap *match* with the given *status*."""
    return StatusedMatch(match=match, status=status, note=note)


def set_status_all(
    matches: Iterable[Match],
    status: Status,
    note: str = "",
) -> List[StatusedMatch]:
    return [set_status(m, status, note) for m in matches]


def status_result(
    result: ScanResult,
    status: Status,
    note: str = "",
) -> List[StatusedMatch]:
    """Apply *status* to every match in *result*."""
    return set_status_all(result.matches, status, note)


def filter_by_status(
    statused: Iterable[StatusedMatch],
    status: Status,
) -> List[StatusedMatch]:
    return [s for s in statused if s.status == status]


def group_by_status(
    statused: Iterable[StatusedMatch],
) -> Dict[Status, List[StatusedMatch]]:
    """Group *statused* matches by their status.

    Returns a dict mapping each :class:`Status` value to the list of
    :class:`StatusedMatch` objects that carry that status.  Statuses with no
    matches are omitted from the result.
    """
    groups: Dict[Status, List[StatusedMatch]] = {}
    for sm in statused:
        groups.setdefault(sm.status, []).append(sm)
    return groups
