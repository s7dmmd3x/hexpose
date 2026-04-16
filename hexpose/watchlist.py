"""Watchlist: flag matches whose values appear in a known-bad value list."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Set

from hexpose.scanner import Match


class Watchlist:
    """A set of known-bad secret values that should always be flagged."""

    def __init__(self, values: Iterable[str] | None = None) -> None:
        self._values: Set[str] = set(values or [])

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "Watchlist":
        """Load a watchlist from a JSON file (list of strings)."""
        p = Path(path)
        if not p.exists():
            return cls()
        raw = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(f"Watchlist file must contain a JSON array, got {type(raw).__name__}")
        return cls(str(v) for v in raw)

    def save(self, path: str | Path) -> None:
        """Persist the watchlist to a JSON file."""
        Path(path).write_text(
            json.dumps(sorted(self._values), indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, value: str) -> None:
        """Add a value to the watchlist."""
        self._values.add(value)

    def remove(self, value: str) -> None:
        """Remove a value; silently ignores missing entries."""
        self._values.discard(value)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def __contains__(self, value: object) -> bool:
        return value in self._values

    def __len__(self) -> int:
        return len(self._values)

    def is_watchlisted(self, match: Match) -> bool:
        """Return True if the match's value appears in the watchlist."""
        return match.value in self._values

    def filter_watchlisted(self, matches: Iterable[Match]) -> list[Match]:
        """Return only the matches whose values are on the watchlist."""
        return [m for m in matches if self.is_watchlisted(m)]
