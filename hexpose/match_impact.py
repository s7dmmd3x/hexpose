"""Assess potential impact of a match based on severity, category, and entropy."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from hexpose.scanner import Match
from hexpose.scanner import ScanResult
from hexpose.entropy import shannon_entropy

_SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_IMPACT_LEVELS = [
    (3.5, "critical"),
    (2.5, "high"),
    (1.5, "medium"),
    (0.5, "low"),
]


@dataclass
class ImpactedMatch:
    match: Match
    impact_score: float
    impact_level: str
    rationale: str

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "impact_score": round(self.impact_score, 3),
            "impact_level": self.impact_level,
            "rationale": self.rationale,
        }


def _impact_level(score: float) -> str:
    for threshold, label in _IMPACT_LEVELS:
        if score >= threshold:
            return label
    return "info"


def assess_impact(match: Match, entropy_weight: float = 0.25) -> ImpactedMatch:
    sev = match.severity.lower() if match.severity else "info"
    base = _SEVERITY_SCORE.get(sev, 0)
    ent = shannon_entropy(match.value.encode() if match.value else b"")
    # Normalise entropy (max ~8 bits) to 0-1 range
    ent_factor = min(ent / 8.0, 1.0)
    score = base + ent_factor * entropy_weight
    level = _impact_level(score)
    rationale = (
        f"severity={sev} (base={base}), "
        f"entropy={ent:.2f} (factor={ent_factor:.2f})"
    )
    return ImpactedMatch(
        match=match,
        impact_score=score,
        impact_level=level,
        rationale=rationale,
    )


def assess_impact_all(result: ScanResult) -> list[ImpactedMatch]:
    return [assess_impact(m) for m in result.matches]
