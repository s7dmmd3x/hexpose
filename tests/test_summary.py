"""Tests for hexpose.summary."""
import pytest
from hexpose.scanner import Match, ScanResult
from hexpose.summary import summarize, format_summary, ScanSummary


def _make_match(value="secret", pattern_name="aws_key", severity="high", offset=0):
    return Match(
        value=value,
        pattern_name=pattern_name,
        severity=severity,
        offset=offset,
        line=1,
    )


def _make_result(matches=None, source="test.bin"):
    return ScanResult(source=source, matches=matches or [])


def test_summarize_empty():
    s = summarize([])
    assert s.total_matches == 0
    assert s.files_scanned == 0
    assert s.files_with_findings == 0
    assert s.unique_values == 0


def test_summarize_single_result_no_matches():
    s = summarize([_make_result()])
    assert s.files_scanned == 1
    assert s.files_with_findings == 0
    assert s.total_matches == 0


def test_summarize_counts_matches():
    r = _make_result([_make_match(), _make_match(value="other", pattern_name="github_token", severity="critical")])
    s = summarize([r])
    assert s.total_matches == 2
    assert s.files_with_findings == 1


def test_summarize_by_severity():
    r = _make_result([
        _make_match(severity="high"),
        _make_match(severity="high", value="v2"),
        _make_match(severity="low", value="v3"),
    ])
    s = summarize([r])
    assert s.by_severity["high"] == 2
    assert s.by_severity["low"] == 1


def test_summarize_by_pattern():
    r = _make_result([
        _make_match(pattern_name="aws_key"),
        _make_match(pattern_name="aws_key", value="v2"),
        _make_match(pattern_name="github_token", value="v3"),
    ])
    s = summarize([r])
    assert s.by_pattern["aws_key"] == 2
    assert s.by_pattern["github_token"] == 1


def test_summarize_unique_values():
    r = _make_result([
        _make_match(value="dup"),
        _make_match(value="dup"),
        _make_match(value="unique"),
    ])
    s = summarize([r])
    assert s.unique_values == 2


def test_summarize_multiple_results():
    r1 = _make_result([_make_match()], source="a.bin")
    r2 = _make_result([], source="b.bin")
    s = summarize([r1, r2])
    assert s.files_scanned == 2
    assert s.files_with_findings == 1


def test_as_dict_keys():
    s = ScanSummary(total_matches=3, files_scanned=1)
    d = s.as_dict()
    assert "total_matches" in d
    assert "by_severity" in d
    assert "unique_values" in d


def test_format_summary_contains_totals():
    r = _make_result([_make_match()])
    s = summarize([r])
    text = format_summary(s)
    assert "1" in text
    assert "Files scanned" in text
