"""Tests for hexpose.match_status."""
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_status import (
    Status,
    StatusedMatch,
    set_status,
    set_status_all,
    status_result,
    filter_by_status,
)


def _make_match(pattern_name="aws_key", value="AKIA1234", offset=0, severity="high"):
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


def _make_result(matches=None):
    return ScanResult(source="test.bin", matches=matches or [])


def test_set_status_returns_statused_match():
    m = _make_match()
    sm = set_status(m, Status.NEW)
    assert isinstance(sm, StatusedMatch)


def test_set_status_default_is_new():
    m = _make_match()
    sm = set_status(m, Status.NEW)
    assert sm.status == Status.NEW


def test_set_status_confirmed():
    m = _make_match()
    sm = set_status(m, Status.CONFIRMED, note="verified manually")
    assert sm.status == Status.CONFIRMED
    assert sm.note == "verified manually"


def test_set_status_false_positive():
    m = _make_match()
    sm = set_status(m, Status.FALSE_POSITIVE)
    assert sm.status == Status.FALSE_POSITIVE


def test_as_dict_contains_expected_keys():
    m = _make_match()
    sm = set_status(m, Status.SUPPRESSED, note="noise")
    d = sm.as_dict()
    assert "pattern_name" in d
    assert "status" in d
    assert "note" in d
    assert d["status"] == "suppressed"
    assert d["note"] == "noise"


def test_str_contains_status_and_pattern():
    m = _make_match()
    sm = set_status(m, Status.FIXED)
    text = str(sm)
    assert "FIXED" in text
    assert "aws_key" in text


def test_set_status_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="github_token", value="ghp_abc")]
    result = set_status_all(matches, Status.NEW)
    assert len(result) == 2
    assert all(isinstance(s, StatusedMatch) for s in result)


def test_set_status_all_empty():
    assert set_status_all([], Status.NEW) == []


def test_status_result_wraps_all_matches():
    result = _make_result(matches=[_make_match(), _make_match()])
    statused = status_result(result, Status.CONFIRMED)
    assert len(statused) == 2
    assert all(s.status == Status.CONFIRMED for s in statused)


def test_status_result_empty_result():
    result = _make_result()
    assert status_result(result, Status.NEW) == []


def test_filter_by_status_keeps_matching():
    matches = [_make_match(), _make_match(pattern_name="jwt", value="eyJ")]
    statused = [
        set_status(matches[0], Status.CONFIRMED),
        set_status(matches[1], Status.FALSE_POSITIVE),
    ]
    confirmed = filter_by_status(statused, Status.CONFIRMED)
    assert len(confirmed) == 1
    assert confirmed[0].match.pattern_name == "aws_key"


def test_filter_by_status_none_match_returns_empty():
    matches = [_make_match()]
    statused = [set_status(matches[0], Status.NEW)]
    result = filter_by_status(statused, Status.FIXED)
    assert result == []
