"""Risk scoring for scan matches based on multiple signals."""
from dataclasses import dataclass, field
from typing import Optional
from hexpose.severity import Severity, parse_severity
from hexpose.entropy import shannon_entropy


@dataclass
class ScoredMatch:
    match: object
    base_score: float
    entropy_bonus: float
    watchlist_bonus: float
    final_score: float
    grade: str


GRADE_THRESHOLDS = [
    (90, "CRITICAL"),
    (70, "HIGH"),
    (50, "MEDIUM"),
    (30, "LOW"),
    (0,  "INFO"),
]

_SEVERITY_BASE = {
    Severity.CRITICAL: 80,
    Severity.HIGH: 60,
    Severity.MEDIUM: 40,
    Severity.LOW: 20,
    Severity.INFO: 5,
}


def _grade(score: float) -> str:
    for threshold, label in GRADE_THRESHOLDS:
        if score >= threshold:
            return label
    return "INFO"


def score_match(match, watchlisted: bool = False) -> ScoredMatch:
    """Compute a numeric risk score (0-100) for a match."""
    severity = parse_severity(getattr(match, "severity", "info"))
    base = _SEVERITY_BASE.get(severity, 5)

    value = getattr(match, "value", "") or ""
    ent = shannon_entropy(value.encode()) if value else 0.0
    entropy_bonus = min(ent * 2.5, 15.0)

    watchlist_bonus = 10.0 if watchlisted else 0.0

    final = min(base + entropy_bonus + watchlist_bonus, 100.0)
    return ScoredMatch(
        match=match,
        base_score=float(base),
        entropy_bonus=round(entropy_bonus, 2),
        watchlist_bonus=watchlist_bonus,
        final_score=round(final, 2),
        grade=_grade(final),
    )


def score_result(result, watchlist=None) -> list:
    """Score all matches in a ScanResult."""
    scored = []
    for match in result.matches:
        wl = watchlist.contains(match.value) if watchlist else False
        scored.append(score_match(match, watchlisted=wl))
    return scored
