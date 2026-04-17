"""Attach and query human-readable labels on matches."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
from hexpose.scanner import Match


@dataclass
class LabeledMatch:
    match: Match
    labels: List[str] = field(default_factory=list)

    def add(self, label: str) -> "LabeledMatch":
        label = label.strip()
        if label and label not in self.labels:
            self.labels.append(label)
        return self

    def has(self, label: str) -> bool:
        return label.strip() in self.labels

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "labels": list(self.labels),
        }


def label_match(match: Match, *labels: str) -> LabeledMatch:
    """Wrap *match* in a LabeledMatch and apply zero or more labels."""
    lm = LabeledMatch(match=match)
    for lbl in labels:
        lm.add(lbl)
    return lm


def matches_with_label(labeled: List[LabeledMatch], label: str) -> List[LabeledMatch]:
    """Return only those LabeledMatches that carry *label*."""
    return [lm for lm in labeled if lm.has(label)]


def label_summary(labeled: List[LabeledMatch]) -> dict:
    """Return a mapping of label -> count across all labeled matches."""
    counts: dict = {}
    for lm in labeled:
        for lbl in lm.labels:
            counts[lbl] = counts.get(lbl, 0) + 1
    return counts
