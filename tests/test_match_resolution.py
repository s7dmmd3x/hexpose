"""Tests for hexpose.match_resolution."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_resolution import (
    ResolutionMatch,
    resolve_match,
    resolve_all,
)


def _make_match(
    pattern_name: str = "aws_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    offset: int = 0,
    severity: str = "critical",
) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test", matches=matches or [])


def test_resolve_match_returns_resolution_match():
    m = _make_match()
    rm = resolve_match(m)
    assert isinstance(rm, ResolutionMatch)


def test_resolve_match_default_is_open():
    rm = resolve_match(_make_match())
    assert rm.resolution == "open"


def test_resolve_match_open_has_no_resolved_at():
    rm = resolve_match(_make_match(), resolution="open")
    assert rm.resolved_at is None


def test_resolve_match_fixed_sets_resolved_at():
    rm = resolve_match(_make_match(), resolution="fixed")
    assert rm.resolved_at is not None


def test_resolve_match_fixed_is_resolved():
    rm = resolve_match(_make_match(), resolution="fixed")
    assert rm.is_resolved() is True


def test_resolve_match_open_is_not_resolved():
    rm = resolve_match(_make_match(), resolution="open")
    assert rm.is_resolved() is False


def test_resolve_match_stores_resolved_by():
    rm = resolve_match(_make_match(), resolution="fixed", resolved_by="alice")
    assert rm.resolved_by == "alice"


def test_resolve_match_strips_resolved_by_whitespace():
    rm = resolve_match(_make_match(), resolution="fixed", resolved_by="  bob  ")
    assert rm.resolved_by == "bob"


def test_resolve_match_stores_notes():
    rm = resolve_match(_make_match(), resolution="fixed", notes=["rotated key"])
    assert "rotated key" in rm.notes


def test_resolve_match_ignores_empty_notes():
    rm = resolve_match(_make_match(), resolution="fixed", notes=["", "  ", "valid"])
    assert rm.notes == ["valid"]


def test_resolve_match_invalid_resolution_raises():
    with pytest.raises(ValueError, match="Invalid resolution"):
        resolve_match(_make_match(), resolution="unknown_status")


def test_resolve_match_custom_timestamp():
    ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    rm = resolve_match(_make_match(), resolution="fixed", timestamp=ts)
    assert rm.resolved_at == ts


def test_as_dict_contains_required_keys():
    rm = resolve_match(_make_match(), resolution="wont_fix", resolved_by="ops")
    d = rm.as_dict()
    for key in ("pattern_name", "value", "offset", "severity", "resolution", "resolved_by", "resolved_at", "notes"):
        assert key in d


def test_as_dict_resolved_at_is_isoformat_string():
    rm = resolve_match(_make_match(), resolution="fixed")
    d = rm.as_dict()
    assert isinstance(d["resolved_at"], str)


def test_str_contains_resolution():
    rm = resolve_match(_make_match(), resolution="false_positive")
    assert "FALSE_POSITIVE" in str(rm)


def test_resolve_all_returns_list_of_resolution_matches():
    result = _make_result([_make_match(), _make_match(pattern_name="github_token")])
    items = resolve_all(result, resolution="duplicate")
    assert len(items) == 2
    assert all(isinstance(i, ResolutionMatch) for i in items)


def test_resolve_all_empty_result_returns_empty_list():
    result = _make_result([])
    assert resolve_all(result) == []
