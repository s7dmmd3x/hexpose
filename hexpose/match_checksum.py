"""Attach checksum metadata to matches for integrity verification."""
from __future__ import annotations

import hashlib
import dataclasses
from typing import Any

from hexpose.scanner import Match, ScanResult


@dataclasses.dataclass
class ChecksumMatch:
    match: Match
    algorithm: str
    checksum: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "algorithm": self.algorithm,
            "checksum": self.checksum,
        }

    def __str__(self) -> str:
        return f"[{self.algorithm}:{self.checksum[:12]}] {self.match.pattern_name}"


def _compute_checksum(value: str, algorithm: str) -> str:
    algo = algorithm.lower()
    if algo == "md5":
        return hashlib.md5(value.encode()).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(value.encode()).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(value.encode()).hexdigest()
    raise ValueError(f"Unsupported checksum algorithm: {algorithm!r}")


def checksum_match(
    match: Match,
    algorithm: str = "sha256",
) -> ChecksumMatch:
    """Wrap *match* with a checksum of its value."""
    checksum = _compute_checksum(match.value, algorithm)
    return ChecksumMatch(match=match, algorithm=algorithm, checksum=checksum)


def checksum_all(
    result: ScanResult,
    algorithm: str = "sha256",
) -> list[ChecksumMatch]:
    """Return ChecksumMatch objects for every match in *result*."""
    return [checksum_match(m, algorithm) for m in result.matches]
