"""Compute similarity between matches based on value and pattern."""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import List, Sequence

from hexpose.scanner import Match


@dataclass
class SimilarMatch:
    match: Match
    similar_to: Match
    ratio: float

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "similar_to_value": self.similar_to.value,
            "ratio": round(self.ratio, 4),
        }


def _similarity_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def find_similar(
    matches: Sequence[Match],
    threshold: float = 0.8,
) -> List[SimilarMatch]:
    """Return pairs of matches whose values are similar above *threshold*."""
    results: List[SimilarMatch] = []
    items = list(matches)
    for i, m1 in enumerate(items):
        for m2 in items[i + 1 :]:
            ratio = _similarity_ratio(m1.value, m2.value)
            if ratio >= threshold:
                results.append(SimilarMatch(match=m1, similar_to=m2, ratio=ratio))
    return results


def deduplicate_by_similarity(
    matches: Sequence[Match],
    threshold: float = 0.95,
) -> List[Match]:
    """Return matches with near-duplicates removed (keeps first occurrence)."""
    kept: List[Match] = []
    for candidate in matches:
        for existing in kept:
            if _similarity_ratio(candidate.value, existing.value) >= threshold:
                break
        else:
            kept.append(candidate)
    return kept
