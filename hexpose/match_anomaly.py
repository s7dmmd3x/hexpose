"""Anomaly detection for matches based on deviation from baseline statistics."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from hexpose.scanner import Match, ScanResult
from hexpose.entropy import shannon_entropy


@dataclass
class AnomalyMatch:
    match: Match
    z_score: float
    is_anomaly: bool
    mean_entropy: float
    stddev_entropy: float
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "z_score": round(self.z_score, 4),
            "is_anomaly": self.is_anomaly,
            "mean_entropy": round(self.mean_entropy, 4),
            "stddev_entropy": round(self.stddev_entropy, 4),
            "notes": self.notes,
        }

    def __str__(self) -> str:
        flag = "[ANOMALY]" if self.is_anomaly else "[normal]"
        return (
            f"{flag} {self.match.pattern_name} z={self.z_score:.2f} "
            f"entropy={shannon_entropy(self.match.value):.2f}"
        )


def _mean_stddev(values: List[float]):
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    stddev = variance ** 0.5
    return mean, stddev


def detect_anomalies(
    matches: Sequence[Match],
    threshold: float = 2.0,
) -> List[AnomalyMatch]:
    """Score each match by how far its entropy deviates from the group mean."""
    if not matches:
        return []

    entropies = [shannon_entropy(m.value) for m in matches]
    mean, stddev = _mean_stddev(entropies)

    results: List[AnomalyMatch] = []
    for match, ent in zip(matches, entropies):
        if stddev == 0.0:
            z = 0.0
        else:
            z = abs(ent - mean) / stddev
        is_anomaly = z >= threshold
        notes = f"entropy={ent:.3f}" + (
            "; high z-score indicates unusual entropy" if is_anomaly else ""
        )
        results.append(
            AnomalyMatch(
                match=match,
                z_score=z,
                is_anomaly=is_anomaly,
                mean_entropy=mean,
                stddev_entropy=stddev,
                notes=notes,
            )
        )
    return results


def detect_anomalies_in_result(
    result: ScanResult,
    threshold: float = 2.0,
) -> List[AnomalyMatch]:
    """Convenience wrapper that operates on a ScanResult."""
    return detect_anomalies(result.matches, threshold=threshold)
