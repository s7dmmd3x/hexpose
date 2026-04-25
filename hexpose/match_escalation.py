"""Match escalation: flag matches that have increased in severity or frequency."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class EscalatedMatch:
    match: Match
    previous_severity: Optional[str]
    current_severity: str
    escalated: bool
    reason: str
    previous_count: int = 0
    current_count: int = 0

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "previous_severity": self.previous_severity,
            "current_severity": self.current_severity,
            "escalated": self.escalated,
            "reason": self.reason,
            "previous_count": self.previous_count,
            "current_count": self.current_count,
        }

    def __str__(self) -> str:
        flag = "[ESCALATED]" if self.escalated else "[stable]"
        return (
            f"{flag} {self.match.pattern_name} "
            f"{self.previous_severity} -> {self.current_severity} | {self.reason}"
        )


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _severity_escalated(prev: Optional[str], curr: str) -> bool:
    if prev is None:
        return False
    return _SEVERITY_RANK.get(curr.lower(), 0) > _SEVERITY_RANK.get(prev.lower(), 0)


def escalate_match(
    match: Match,
    baseline_severity: Optional[str] = None,
    previous_count: int = 0,
    current_count: int = 0,
) -> EscalatedMatch:
    """Determine whether a single match represents an escalation."""
    sev_up = _severity_escalated(baseline_severity, match.severity)
    count_up = current_count > previous_count > 0

    reasons = []
    if sev_up:
        reasons.append("severity increased")
    if count_up:
        reasons.append("occurrence count increased")
    if baseline_severity is None and current_count > 0:
        reasons.append("new finding")

    escalated = bool(reasons)
    reason = "; ".join(reasons) if reasons else "no change"

    return EscalatedMatch(
        match=match,
        previous_severity=baseline_severity,
        current_severity=match.severity,
        escalated=escalated,
        reason=reason,
        previous_count=previous_count,
        current_count=current_count,
    )


def escalate_result(
    result: ScanResult,
    baseline: Optional[dict] = None,
) -> List[EscalatedMatch]:
    """Escalate all matches in a ScanResult against an optional baseline dict.

    *baseline* maps ``pattern_name`` to ``{"severity": str, "count": int}``.
    """
    baseline = baseline or {}
    out: List[EscalatedMatch] = []
    for match in result.matches:
        entry = baseline.get(match.pattern_name, {})
        out.append(
            escalate_match(
                match,
                baseline_severity=entry.get("severity"),
                previous_count=entry.get("count", 0),
                current_count=1,
            )
        )
    return out
