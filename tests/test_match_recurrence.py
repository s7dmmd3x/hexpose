"""Tests for hexpose.match_recurrence."""
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_recurrence import (
    RecurringMatch,
    build_recurrence,
    top_recurring,
    _match_key,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_match(pattern_name: str = "aws_key", value: str = "AKIA1234", offset: int = 0) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity="high")


def _make_result(*matches: Match) -> ScanResult:
    return ScanResult(source="test", matches=list(matches))


# ---------------------------------------------------------------------------
# _match_key
# ---------------------------------------------------------------------------

def test_match_key_uses_pattern_and_value():
    m = _make_match("jwt", "tok.en.val")
    assert _match_key(m) == "jwt::tok.en.val"


def test_match_key_same_for_different_offsets():
    m1 = _make_match("pw", "secret", offset=0)
    m2 = _make_match("pw", "secret", offset=99)
    assert _match_key(m1) == _match_key(m2)


# ---------------------------------------------------------------------------
# build_recurrence
# ---------------------------------------------------------------------------

def test_build_recurrence_empty_results():
    assert build_recurrence([]) == []


def test_build_recurrence_single_result_single_match():
    m = _make_match()
    result = build_recurrence([_make_result(m)])
    assert len(result) == 1
    r = result[0]
    assert isinstance(r, RecurringMatch)
    assert r.seen_count == 1
    assert r.first_seen == r.last_seen


def test_build_recurrence_counts_across_two_results():
    m = _make_match()
    recs = build_recurrence([_make_result(m), _make_result(m)], scan_ids=["s1", "s2"])
    assert len(recs) == 1
    assert recs[0].seen_count == 2
    assert recs[0].first_seen == "s1"
    assert recs[0].last_seen == "s2"


def test_build_recurrence_distinct_matches_not_merged():
    m1 = _make_match("aws_key", "AKIA1111")
    m2 = _make_match("aws_key", "AKIA2222")
    recs = build_recurrence([_make_result(m1, m2)])
    assert len(recs) == 2


def test_build_recurrence_scan_ids_recorded():
    m = _make_match()
    recs = build_recurrence(
        [_make_result(m), _make_result(m), _make_result(m)],
        scan_ids=["a", "b", "c"],
    )
    assert recs[0].scan_ids == ["a", "b", "c"]


def test_build_recurrence_default_scan_ids_are_strings():
    m = _make_match()
    recs = build_recurrence([_make_result(m), _make_result(m)])
    assert recs[0].scan_ids == ["0", "1"]


def test_build_recurrence_raises_on_mismatched_scan_ids():
    with pytest.raises(ValueError):
        build_recurrence([_make_result()], scan_ids=["a", "b"])


# ---------------------------------------------------------------------------
# as_dict
# ---------------------------------------------------------------------------

def test_as_dict_contains_required_keys():
    m = _make_match()
    r = RecurringMatch(match=m, seen_count=3, first_seen="s0", last_seen="s2", scan_ids=["s0", "s1", "s2"])
    d = r.as_dict()
    for key in ("pattern_name", "value", "offset", "seen_count", "first_seen", "last_seen", "scan_ids"):
        assert key in d


def test_as_dict_values_match_fields():
    m = _make_match("github_token", "ghp_xyz", offset=10)
    r = RecurringMatch(match=m, seen_count=2, first_seen="run1", last_seen="run2", scan_ids=["run1", "run2"])
    d = r.as_dict()
    assert d["pattern_name"] == "github_token"
    assert d["value"] == "ghp_xyz"
    assert d["seen_count"] == 2


# ---------------------------------------------------------------------------
# top_recurring
# ---------------------------------------------------------------------------

def test_top_recurring_returns_sorted_by_count():
    m1 = _make_match("a", "v1")
    m2 = _make_match("b", "v2")
    r1 = RecurringMatch(match=m1, seen_count=5, first_seen="0", last_seen="4", scan_ids=[])
    r2 = RecurringMatch(match=m2, seen_count=2, first_seen="0", last_seen="1", scan_ids=[])
    top = top_recurring([r2, r1], n=2)
    assert top[0].seen_count == 5


def test_top_recurring_respects_n():
    matches = [
        RecurringMatch(match=_make_match("p", str(i)), seen_count=i, first_seen="0", last_seen="0", scan_ids=[])
        for i in range(10)
    ]
    assert len(top_recurring(matches, n=3)) == 3
