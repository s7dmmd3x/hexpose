"""Triage module: assign risk levels to scan results based on entropy, severity, and watchlist."""

from dataclasses import dataclass, field
from typing import List

from hexpose.scanner import Match, ScanResult
from hexpose.entropy import shannon_entropy, high_entropy
from hexpose.watchlist_annotator import watchlisted_matches
from hexpose.watchlist import Watchlist


RISK_CRITICAL = "critical"
RISK_HIGH = "high"
RISK_MEDIUM = "medium"
RISK_LOW = "low"


@dataclass
class TriagedMatch:
    match: Match
    risk: str
    reasons: List[str] = field(default_factory=list)


def _risk_from_severity(severity: str) -> str:
    s = severity.lower()
    if s == "critical":
        return RISK_CRITICAL
    if s == "high":
        return RISK_HIGH
    if s == "medium":
        return RISK_MEDIUM
    return RISK_LOW


def triage_match(match: Match, watchlist: Watchlist | None = None) -> TriagedMatch:
    reasons: List[str] = []
    risk = _risk_from_severity(match.severity)

    entropy = shannon_entropy(match.value.encode())
    if high_entropy(match.value.encode()):
        reasons.append(f"high entropy ({entropy:.2f})")
        if risk == RISK_MEDIUM:
            risk = RISK_HIGH
        elif risk == RISK_LOW:
            risk = RISK_MEDIUM

    if watchlist and watchlist.contains(match.value):
        reasons.append("value on watchlist")
        risk = RISK_CRITICAL

    if not reasons:
        reasons.append("severity-based")

    return TriagedMatch(match=match, risk=risk, reasons=reasons)


def triage_result(result: ScanResult, watchlist: Watchlist | None = None) -> List[TriagedMatch]:
    return [triage_match(m, watchlist) for m in result.matches]
