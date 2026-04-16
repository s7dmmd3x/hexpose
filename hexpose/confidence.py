"""Confidence scoring for matches based on entropy, context, and pattern weight."""
from dataclasses import dataclass, field
from typing import Optional
from hexpose.scanner import Match
from hexpose.entropy import shannon_entropy


@dataclass
class ConfidenceResult:
    match: Match
    score: float  # 0.0 - 1.0
    level: str
    reasons: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern": self.match.pattern_name,
            "offset": self.match.offset,
            "score": round(self.score, 3),
            "level": self.level,
            "reasons": self.reasons,
        }


def _level(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def _entropy_factor(value: str) -> tuple[float, Optional[str]]:
    e = shannon_entropy(value.encode())
    if e >= 4.0:
        return 0.35, f"high entropy ({e:.2f})"
    if e >= 2.5:
        return 0.15, f"moderate entropy ({e:.2f})"
    return 0.0, None


def _severity_factor(severity: str) -> tuple[float, str]:
    mapping = {"critical": 0.40, "high": 0.30, "medium": 0.20, "low": 0.05, "info": 0.0}
    s = severity.lower()
    weight = mapping.get(s, 0.10)
    return weight, f"severity={s}"


def score_confidence(match: Match) -> ConfidenceResult:
    reasons = []
    total = 0.0

    sev_w, sev_r = _severity_factor(match.severity)
    total += sev_w
    reasons.append(sev_r)

    ent_w, ent_r = _entropy_factor(match.value)
    total += ent_w
    if ent_r:
        reasons.append(ent_r)

    if len(match.value) >= 20:
        total += 0.15
        reasons.append("long value (>=20 chars)")
    elif len(match.value) >= 8:
        total += 0.05
        reasons.append("moderate length (>=8 chars)")

    total = min(total, 1.0)
    return ConfidenceResult(match=match, score=total, level=_level(total), reasons=reasons)


def score_confidence_all(matches: list) -> list:
    return [score_confidence(m) for m in matches]
