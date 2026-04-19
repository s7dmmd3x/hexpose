"""Match verdict: assign a human-readable verdict to a match based on confidence and severity."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from hexpose.scanner import Match
from hexpose.confidence import score_confidence


VERDICT_CONFIRMED = "confirmed"
VERDICT_LIKELY = "likely"
VERDICT_UNCERTAIN = "uncertain"
VERDICT_UNLIKELY = "unlikely"


@dataclass
class VerdictMatch:
    match: Match
    verdict: str
    reason: str
    confidence_score: float
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "verdict": self.verdict,
            "reason": self.reason,
            "confidence_score": round(self.confidence_score, 3),
        }


def _derive_verdict(confidence_score: float, severity: str) -> tuple[str, str]:
    sev = severity.lower()
    if confidence_score >= 0.75 and sev in ("critical", "high"):
        return VERDICT_CONFIRMED, "High confidence and high severity"
    if confidence_score >= 0.55:
        return VERDICT_LIKELY, "Moderate-to-high confidence"
    if confidence_score >= 0.35:
        return VERDICT_UNCERTAIN, "Low-to-moderate confidence"
    return VERDICT_UNLIKELY, "Low confidence score"


def assign_verdict(match: Match, raw_bytes: Optional[bytes] = None) -> VerdictMatch:
    cr = score_confidence(match, raw_bytes=raw_bytes)
    verdict, reason = _derive_verdict(cr.score, match.severity)
    return VerdictMatch(
        match=match,
        verdict=verdict,
        reason=reason,
        confidence_score=cr.score,
    )


def assign_verdict_all(
    matches: list[Match], raw_bytes: Optional[bytes] = None
) -> list[VerdictMatch]:
    return [assign_verdict(m, raw_bytes=raw_bytes) for m in matches]
