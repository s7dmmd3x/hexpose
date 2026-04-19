"""match_scope.py – attach a scope (region/section) label to a match.

A 'scope' describes where in the binary the match was found, e.g.
'.text', '.data', 'heap', 'stack', or a custom region name.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class ScopedMatch:
    match: Match
    scope: str
    region_start: Optional[int] = None
    region_end: Optional[int] = None

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "scope": self.scope,
            "region_start": self.region_start,
            "region_end": self.region_end,
        }

    def __str__(self) -> str:
        return f"[{self.scope}] {self.match.pattern_name} @ {self.match.offset}"


def scope_match(
    match: Match,
    scope: str,
    region_start: Optional[int] = None,
    region_end: Optional[int] = None,
) -> ScopedMatch:
    """Attach a scope label to a single match."""
    return ScopedMatch(
        match=match,
        scope=scope,
        region_start=region_start,
        region_end=region_end,
    )


def scope_all(
    result: ScanResult,
    scope: str,
    region_start: Optional[int] = None,
    region_end: Optional[int] = None,
) -> list[ScopedMatch]:
    """Attach the same scope to every match in a ScanResult."""
    return [
        scope_match(m, scope, region_start, region_end)
        for m in result.matches
    ]


def scope_by_offset(
    matches: Iterable[Match],
    regions: list[dict],
) -> list[ScopedMatch]:
    """Assign scope based on offset falling within named regions.

    regions is a list of dicts with keys: 'name', 'start', 'end'.
    Matches outside all regions receive scope 'unknown'.
    """
    scoped: list[ScopedMatch] = []
    for m in matches:
        assigned = "unknown"
        rs = re = None
        for region in regions:
            if region["start"] <= m.offset < region["end"]:
                assigned = region["name"]
                rs, re = region["start"], region["end"]
                break
        scoped.append(ScopedMatch(match=m, scope=assigned, region_start=rs, region_end=re))
    return scoped
