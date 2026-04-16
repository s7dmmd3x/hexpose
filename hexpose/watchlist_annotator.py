"""Annotate ScanResult matches with a 'watchlisted' metadata flag."""

from __future__ import annotations

from hexpose.scanner import Match, ScanResult
from hexpose.watchlist import Watchlist

WATCHLIST_KEY = "watchlisted"


def annotate_match(match: Match, watchlist: Watchlist) -> Match:
    """Return the match with 'watchlisted' set in its metadata.

    The original Match object is mutated in-place (metadata dict update)
    and also returned for convenience.
    """
    if match.metadata is None:
        # Match is a dataclass; metadata may be a plain dict or None.
        # We assign a new dict to avoid mutating a shared default.
        object.__setattr__(match, "metadata", {})
    match.metadata[WATCHLIST_KEY] = watchlist.is_watchlisted(match)
    return match


def annotate_result(result: ScanResult, watchlist: Watchlist) -> ScanResult:
    """Annotate every match in *result* with the watchlist flag.

    Returns the same ScanResult object (mutation in-place).
    """
    for match in result.matches:
        annotate_match(match, watchlist)
    return result


def watchlisted_matches(result: ScanResult, watchlist: Watchlist) -> list[Match]:
    """Return a list of matches from *result* that are on the watchlist."""
    return watchlist.filter_watchlisted(result.matches)
