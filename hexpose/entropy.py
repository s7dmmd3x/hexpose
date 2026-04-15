"""Shannon entropy utilities used to rank and filter scan matches."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str | bytes) -> float:
    """Return the Shannon entropy (bits per symbol) of *data*.

    Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def high_entropy(value: str | bytes, threshold: float = 3.5) -> bool:
    """Return True when *value* has entropy >= *threshold*.

    A threshold of ~3.5 bits/char works well for Base64-encoded secrets;
    adjust downward (e.g. 2.5) for hex strings.
    """
    return shannon_entropy(value) >= threshold


def entropy_label(value: str | bytes) -> str:
    """Return a human-readable entropy label for *value*."""
    e = shannon_entropy(value)
    if e >= 4.5:
        return "very-high"
    if e >= 3.5:
        return "high"
    if e >= 2.5:
        return "medium"
    if e >= 1.5:
        return "low"
    return "very-low"
