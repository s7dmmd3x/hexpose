"""Filtering and suppression of scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Iterable, List, Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class FilterConfig:
    """Configuration for result filtering."""

    min_severity: Optional[str] = None          # low | medium | high | critical
    include_patterns: List[str] = field(default_factory=list)  # pattern name globs
    exclude_patterns: List[str] = field(default_factory=list)  # pattern name globs
    min_entropy: Optional[float] = None
    max_offset: Optional[int] = None


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _severity_ok(match: Match, min_severity: Optional[str]) -> bool:
    if min_severity is None:
        return True
    rank = _SEVERITY_RANK.get(match.severity.lower(), 0)
    threshold = _SEVERITY_RANK.get(min_severity.lower(), 0)
    return rank >= threshold


def _pattern_name_ok(match: Match, include: List[str], exclude: List[str]) -> bool:
    name = match.pattern_name
    if include and not any(fnmatch(name, g) for g in include):
        return False
    if exclude and any(fnmatch(name, g) for g in exclude):
        return False
    return True


def filter_match(match: Match, cfg: FilterConfig) -> bool:
    """Return True if *match* passes all filter criteria."""
    if not _severity_ok(match, cfg.min_severity):
        return False
    if not _pattern_name_ok(match, cfg.include_patterns, cfg.exclude_patterns):
        return False
    if cfg.min_entropy is not None and (match.entropy or 0.0) < cfg.min_entropy:
        return False
    if cfg.max_offset is not None and match.offset > cfg.max_offset:
        return False
    return True


def filter_matches(matches: Iterable[Match], cfg: FilterConfig) -> List[Match]:
    """Return only the matches that pass *cfg*."""
    return [m for m in matches if filter_match(m, cfg)]


def apply_filter(result: ScanResult, cfg: FilterConfig) -> ScanResult:
    """Return a new ScanResult containing only matches that pass *cfg*."""
    kept = filter_matches(result.matches, cfg)
    return ScanResult(source=result.source, matches=kept)
