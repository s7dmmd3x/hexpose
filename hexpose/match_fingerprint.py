"""Fingerprinting for Match objects — stable IDs for dedup, baseline, and suppression."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List

from hexpose.scanner import Match, ScanResult


@dataclass
class FingerprintedMatch:
    match: Match
    fingerprint: str

    def as_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
        }


def _compute_fingerprint(match: Match, *, include_offset: bool = False) -> str:
    """Return a SHA-256 hex fingerprint for a match.

    By default the fingerprint is stable across re-scans of the same content
    (pattern_name + value).  Pass include_offset=True to also incorporate the
    byte offset, making it unique per occurrence.
    """
    parts = [match.pattern_name, match.value]
    if include_offset:
        parts.append(str(match.offset))
    raw = "\x00".join(parts).encode()
    return hashlib.sha256(raw).hexdigest()


def fingerprint_match(
    match: Match, *, include_offset: bool = False
) -> FingerprintedMatch:
    fp = _compute_fingerprint(match, include_offset=include_offset)
    return FingerprintedMatch(match=match, fingerprint=fp)


def fingerprint_result(
    result: ScanResult, *, include_offset: bool = False
) -> List[FingerprintedMatch]:
    return [
        fingerprint_match(m, include_offset=include_offset)
        for m in result.matches
    ]


def unique_fingerprints(result: ScanResult, *, include_offset: bool = False) -> List[str]:
    """Return a sorted, deduplicated list of fingerprints for a result."""
    fps = {_compute_fingerprint(m, include_offset=include_offset) for m in result.matches}
    return sorted(fps)
