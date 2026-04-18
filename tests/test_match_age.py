"""Tests for hexpose.match_age."""
from datetime import datetime, timezone, timedelta

import pytest

from hexpose.match_age import age_match, age_result, AgedMatch
from hexpose.scanner import Match, ScanResult
from hexpose.patterns import SecretPattern
import re


def _make_match(name="aws_key", value="AKIAIOSFODNN7EXAMPLE", offset=0) -> Match:
    pat = SecretPattern(name=name, regex=re.compile(value), severity="high", description="")
    return Match(pattern=pat, value=value, offset=offset)


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test", matches=matches or [])


NOW = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
OLD = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)  # 31 days before NOW


def test_age_match_returns_aged_match():
    m = _make_match()
    result = age_match(m, {}, now=NOW)
    assert isinstance(result, AgedMatch)


def test_age_match_new_when_not_in_baseline():
    m = _make_match()
    result = age_match(m, {}, now=NOW)
    assert result.is_new is True
    assert result.first_seen is None
    assert result.age_days is None


def test_age_match_not_new_when_in_baseline():
    m = _make_match()
    key = f"{m.pattern_name}:{m.offset}:{m.value}"
    result = age_match(m, {key: OLD}, now=NOW)
    assert result.is_new is False
    assert result.first_seen == OLD


def test_age_match_age_days_correct():
    m = _make_match()
    key = f"{m.pattern_name}:{m.offset}:{m.value}"
    result = age_match(m, {key: OLD}, now=NOW)
    assert abs(result.age_days - 31.0) < 0.01


def test_age_match_last_seen_equals_now():
    m = _make_match()
    result = age_match(m, {}, now=NOW)
    assert result.last_seen == NOW


def test_as_dict_contains_expected_keys():
    m = _make_match()
    result = age_match(m, {}, now=NOW)
    d = result.as_dict()
    for key in ("pattern_name", "offset", "first_seen", "last_seen", "age_days", "is_new"):
        assert key in d


def test_as_dict_is_new_true_when_new():
    m = _make_match()
    d = age_match(m, {}, now=NOW).as_dict()
    assert d["is_new"] is True


def test_age_result_returns_list_of_aged_matches():
    r = _make_result([_make_match(), _make_match(name="github", value="ghp_abc", offset=10)])
    results = age_result(r, {}, now=NOW)
    assert len(results) == 2
    assert all(isinstance(x, AgedMatch) for x in results)


def test_age_result_empty_matches():
    r = _make_result([])
    assert age_result(r, {}, now=NOW) == []
