"""Suppression list: ignore known-safe findings by fingerprint or value."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List, Set

from hexpose.scanner import Match


def _fingerprint(match: Match) -> str:
    """Stable SHA-256 fingerprint for a match (pattern + raw value)."""
    key = f"{match.pattern_name}:{match.value}"
    return hashlib.sha256(key.encode()).hexdigest()


class SuppressionList:
    """Manages a set of suppressed finding fingerprints."""

    def __init__(self, fingerprints: Set[str] | None = None) -> None:
        self._fingerprints: Set[str] = fingerprints or set()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "SuppressionList":
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text())
        return cls(set(data.get("suppressed", [])))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps({"suppressed": sorted(self._fingerprints)}, indent=2)
        )

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def add(self, match: Match) -> str:
        """Suppress *match* and return its fingerprint."""
        fp = _fingerprint(match)
        self._fingerprints.add(fp)
        return fp

    def is_suppressed(self, match: Match) -> bool:
        return _fingerprint(match) in self._fingerprints

    def filter(self, matches: List[Match]) -> List[Match]:
        """Return only matches that are *not* suppressed."""
        return [m for m in matches if not self.is_suppressed(m)]

    def __len__(self) -> int:
        return len(self._fingerprints)
