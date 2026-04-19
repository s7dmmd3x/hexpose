"""Formatting helpers for ClassifiedMatch results."""
from __future__ import annotations

from collections import Counter
from typing import List

from hexpose.match_classification import ClassifiedMatch

_ANSI = {
    "definite": "\033[91m",
    "probable": "\033[93m",
    "possible": "\033[96m",
    "reset": "\033[0m",
}


def _c(tier: str, text: str, colour: bool = True) -> str:
    if not colour:
        return text
    code = _ANSI.get(tier, "")
    return f"{code}{text}{_ANSI['reset']}"


def format_classified_match(cm: ClassifiedMatch, colour: bool = True) -> str:
    tier_str = _c(cm.tier, cm.tier.upper(), colour)
    kws = ", ".join(cm.keywords_matched) if cm.keywords_matched else "—"
    return (
        f"[{tier_str}] {cm.match.pattern_name} "
        f"| category={cm.category} "
        f"| keywords={kws} "
        f"| severity={cm.match.severity or 'unknown'} "
        f"| offset={cm.match.offset}"
    )


def format_classification_report(
    classified: List[ClassifiedMatch], colour: bool = True
) -> str:
    if not classified:
        return "No classified matches."
    lines = [format_classified_match(cm, colour=colour) for cm in classified]
    return "\n".join(lines)


def classification_summary(classified: List[ClassifiedMatch]) -> str:
    if not classified:
        return "Classifications: none"
    cat_counts: Counter = Counter(cm.category for cm in classified)
    tier_counts: Counter = Counter(cm.tier for cm in classified)
    cat_str = ", ".join(f"{k}:{v}" for k, v in cat_counts.most_common())
    tier_str = ", ".join(f"{k}:{v}" for k, v in tier_counts.most_common())
    return f"Classifications: {len(classified)} match(es) | categories=[{cat_str}] | tiers=[{tier_str}]"
