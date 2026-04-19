"""Rank matches by combined score, entropy, and severity."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List

from hexpose.scanner import Match
from hexpose.entropy import shannon_entropy
from hexpose.severity import parse_severity

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class RankedMatch:
    match: Match
    entropy_score: float
    severity_weight: int
    rank_score: float

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "entropy_score": round(self.entropy_score, 4),
            "severity_weight": self.severity_weight,
            "rank_score": round(self.rank_score, 4),
        }


def _compute_rank(match: Match, entropy_weight: float = 0.4, severity_weight: float = 0.6) -> RankedMatch:
    ent = shannon_entropy(match.value.encode())
    sev_str = match.severity if isinstance(match.severity, str) else str(match.severity)
    sev_w = _SEVERITY_WEIGHT.get(sev_str.lower(), 0)
    rank = entropy_weight * ent + severity_weight * sev_w
    return RankedMatch(match=match, entropy_score=ent, severity_weight=sev_w, rank_score=rank)


def rank_matches(matches: List[Match], entropy_weight: float = 0.4, severity_weight: float = 0.6) -> List[RankedMatch]:
    """Return matches sorted by rank_score descending."""
    ranked = [_compute_rank(m, entropy_weight, severity_weight) for m in matches]
    ranked.sort(key=lambda r: r.rank_score, reverse=True)
    return ranked


def top_n(matches: List[Match], n: int = 10, **kwargs) -> List[RankedMatch]:
    """Return the top-n ranked matches."""
    return rank_matches(matches, **kwargs)[:n]


def filter_by_severity(matches: List[RankedMatch], min_severity: str) -> List[RankedMatch]:
    """Return only ranked matches at or above the given minimum severity level.

    Args:
        matches: A list of RankedMatch objects to filter.
        min_severity: Minimum severity string (e.g. ``"medium"``). Matches with
            a severity weight below this threshold are excluded.

    Returns:
        Filtered list preserving the existing sort order.
    """
    threshold = _SEVERITY_WEIGHT.get(min_severity.lower())
    if threshold is None:
        raise ValueError(
            f"Unknown severity level {min_severity!r}. "
            f"Valid values: {list(_SEVERITY_WEIGHT.keys())}"
        )
    return [r for r in matches if r.severity_weight >= threshold]
