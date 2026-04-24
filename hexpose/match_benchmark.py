"""match_benchmark.py – benchmark matches against historical baselines.

Provides a BenchmarkMatch wrapper that records whether a match's risk score
falls above, below, or within a historical percentile band.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from hexpose.scanner import Match


@dataclass
class BenchmarkMatch:
    match: Match
    score: float
    baseline_mean: float
    baseline_stddev: float
    z_score: float
    rating: str  # "above", "within", "below"

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "score": round(self.score, 4),
            "baseline_mean": round(self.baseline_mean, 4),
            "baseline_stddev": round(self.baseline_stddev, 4),
            "z_score": round(self.z_score, 4),
            "rating": self.rating,
        }

    def __str__(self) -> str:
        return (
            f"[{self.rating.upper()}] {self.match.pattern_name} "
            f"score={self.score:.3f} z={self.z_score:.2f}"
        )


def _mean_stddev(values: Sequence[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, variance ** 0.5


def _rating(z: float, threshold: float = 1.0) -> str:
    if z > threshold:
        return "above"
    if z < -threshold:
        return "below"
    return "within"


def benchmark_match(
    match: Match,
    score: float,
    historical_scores: Sequence[float],
    threshold: float = 1.0,
) -> BenchmarkMatch:
    """Wrap *match* with benchmark metadata derived from *historical_scores*."""
    mean, stddev = _mean_stddev(list(historical_scores))
    if stddev == 0.0:
        z = 0.0
    else:
        z = (score - mean) / stddev
    return BenchmarkMatch(
        match=match,
        score=score,
        baseline_mean=mean,
        baseline_stddev=stddev,
        z_score=z,
        rating=_rating(z, threshold),
    )


def benchmark_all(
    matches: Sequence[Match],
    scores: Sequence[float],
    historical_scores: Sequence[float],
    threshold: float = 1.0,
) -> List[BenchmarkMatch]:
    """Benchmark every match using its paired score against *historical_scores*."""
    return [
        benchmark_match(m, s, historical_scores, threshold)
        for m, s in zip(matches, scores)
    ]
