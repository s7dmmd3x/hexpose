"""match_risk: aggregate risk scoring combining severity, confidence, and impact."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
from hexpose.scanner import Match, ScanResult


@dataclass
class RiskMatch:
    match: Match
    risk_score: float
    risk_level: str
    factors: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "risk_score": round(self.risk_score, 3),
            "risk_level": self.risk_level,
            "factors": self.factors,
        }


_SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}


def _severity_weight(severity: str) -> float:
    return _SEVERITY_WEIGHT.get(severity.lower(), 0.1)


def _entropy_factor(value: str) -> float:
    from hexpose.entropy import shannon_entropy
    e = shannon_entropy(value.encode())
    return min(e / 8.0, 1.0)


def _length_factor(value: str) -> float:
    return min(len(value) / 64.0, 1.0)


def _level(score: float) -> str:
    if score >= 0.75:
        return "critical"
    if score >= 0.5:
        return "high"
    if score >= 0.3:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def assess_risk(match: Match) -> RiskMatch:
    sw = _severity_weight(match.severity)
    ef = _entropy_factor(match.value)
    lf = _length_factor(match.value)
    score = sw * 0.6 + ef * 0.25 + lf * 0.15
    return RiskMatch(
        match=match,
        risk_score=score,
        risk_level=_level(score),
        factors={"severity_weight": sw, "entropy_factor": ef, "length_factor": lf},
    )


def assess_risk_all(result: ScanResult) -> List[RiskMatch]:
    return [assess_risk(m) for m in result.matches]
