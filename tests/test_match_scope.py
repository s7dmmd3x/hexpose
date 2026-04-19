"""Tests for hexpose.match_scope and hexpose.scope_report."""
import pytest
from unittest.mock import MagicMock

from hexpose.match_scope import (
    ScopedMatch,
    scope_match,
    scope_all,
    scope_by_offset,
)
from hexpose.scope_report import format_scoped_match, format_scope_report, scope_summary


def _make_match(pattern_name="aws_key", value="AKIA1234567890ABCDEF", offset=0, severity="high"):
    m = MagicMock()
    m.pattern_name = pattern_name
    m.value = value
    m.offset = offset
    m.severity = severity
    return m


def _make_result(matches):
    r = MagicMock()
    r.matches = matches
    return r


def test_scope_match_returns_scoped_match():
    m = _make_match()
    sm = scope_match(m, "heap")
    assert isinstance(sm, ScopedMatch)


def test_scope_match_stores_scope():
    m = _make_match()
    sm = scope_match(m, ".data", region_start=0, region_end=1024)
    assert sm.scope == ".data"
    assert sm.region_start == 0
    assert sm.region_end == 1024


def test_scope_match_as_dict_keys():
    m = _make_match()
    d = scope_match(m, "stack").as_dict()
    for key in ("pattern_name", "value", "offset", "severity", "scope", "region_start", "region_end"):
        assert key in d


def test_scope_match_str_contains_scope():
    m = _make_match()
    sm = scope_match(m, ".text")
    assert ".text" in str(sm)


def test_scope_all_returns_list_per_match():
    matches = [_make_match(offset=i) for i in range(3)]
    result = _make_result(matches)
    scoped = scope_all(result, "heap")
    assert len(scoped) == 3
    assert all(s.scope == "heap" for s in scoped)


def test_scope_all_empty_result():
    result = _make_result([])
    assert scope_all(result, "heap") == []


def test_scope_by_offset_assigns_correct_region():
    regions = [
        {"name": ".text", "start": 0, "end": 512},
        {"name": ".data", "start": 512, "end": 1024},
    ]
    matches = [_make_match(offset=100), _make_match(offset=600)]
    scoped = scope_by_offset(matches, regions)
    assert scoped[0].scope == ".text"
    assert scoped[1].scope == ".data"


def test_scope_by_offset_unknown_when_outside_all_regions():
    regions = [{"name": ".text", "start": 0, "end": 100}]
    m = _make_match(offset=999)
    scoped = scope_by_offset([m], regions)
    assert scoped[0].scope == "unknown"
    assert scoped[0].region_start is None


def test_format_scoped_match_contains_scope():
    m = _make_match()
    sm = scope_match(m, ".bss")
    text = format_scoped_match(sm)
    assert ".bss" in text


def test_format_scope_report_empty():
    assert "No" in format_scope_report([])


def test_format_scope_report_non_empty():
    sm = scope_match(_make_match(), "heap")
    report = format_scope_report([sm])
    assert "heap" in report


def test_scope_summary_groups_by_scope():
    matches = [_make_match(offset=i) for i in range(4)]
    scoped = [scope_match(matches[0], "heap"), scope_match(matches[1], "heap"),
              scope_match(matches[2], ".data"), scope_match(matches[3], ".text")]
    summary = scope_summary(scoped)
    assert "heap" in summary
    assert ".data" in summary


def test_scope_summary_empty():
    assert "No" in scope_summary([])
