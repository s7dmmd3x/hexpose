"""match_signal.py – attach signal strength metadata to a Match.

A 'signal' combines entropy, severity weight, and pattern confidence
into a single normalised score in [0.0, 1.0] and a human-readable
label (strong / moderate / weak).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from hexpose.scanner import Match, ScanResult
from hexpose.entropy import shannon_entropy

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}


@dataclass
class SignalMatch:
    match: Match
    signal_score: float          # 0.0 – 1.0
    signal_label: str            # strong / moderate / weak
    entropy: float
    severity_weight: float

    def as_dict(self) -> dict:
        return {
            "pattern": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "entropy": round(self.entropy, 4),
            "severity_weight": self.severity_weight,
            "signal_score": round(self.signal_score, 4),
            "signal_label": self.signal_label,
        }

    def __str__(self) -> str:
        return (
            f"[{self.signal_label.upper()}] {self.match.pattern_name} "
            f"score={self.signal_score:.3f}"
        )


def _label(score: float) -> str:
    if score >= 0.65:
        return "strong"
    if score >= 0.35:
        return "moderate"
    return "weak"


def _entropy_factor(value: str) -> float:
    """Normalise Shannon entropy of *value* to [0, 1] (max ~8 bits/char)."""
    raw = shannon_entropy(value.encode())
    return min(raw / 8.0, 1.0)


def signal_match(match: Match) -> SignalMatch:
    """Compute signal strength for a single *match*."""
    sev = (match.severity or "").lower()
    sev_w = _SEVERITY_WEIGHT.get(sev, 0.25)
    ent_f = _entropy_factor(match.value)
    score = round((sev_w * 0.6) + (ent_f * 0.4), 6)
    return SignalMatch(
        match=match,
        signal_score=score,
        signal_label=_label(score),
        entropy=shannon_entropy(match.value.encode()),
        severity_weight=sev_w,
    )


def signal_all(result: ScanResult) -> List[SignalMatch]:
    """Return a :class:`SignalMatch` for every match in *result*."""
    return [signal_match(m) for m in result.matches]
