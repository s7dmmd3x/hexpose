"""Tests for hexpose.trend."""
import pytest
from hexpose.timeline import Timeline
from hexpose.trend import (
    TrendPoint,
    TrendReport,
    trend_point_from_timeline,
    build_trend_report,
    format_trend_report,
)
from hexpose.scanner import Match, ScanResult


def _make_match(pattern_name: str = "aws_key", severity: str = "high", value: str = "AKIA1234") -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=0, severity=severity)


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test.bin", matches=matches or [])


def _timeline_with_results(*results) -> Timeline:
    t = Timeline()
    for r in results:
        t.add_event(r)
    return t


def test_trend_point_from_empty_timeline():
    t = Timeline()
    pt = trend_point_from_timeline(t, "v1")
    assert pt.label == "v1"
    assert pt.total_matches == 0
    assert pt.by_severity == {}


def test_trend_point_counts_matches():
    r = _make_result([_make_match(), _make_match(severity="critical")])
    t = _timeline_with_results(r)
    pt = trend_point_from_timeline(t, "v1")
    assert pt.total_matches == 2


def test_trend_point_by_severity():
    r = _make_result([_make_match(severity="high"), _make_match(severity="high"), _make_match(severity="low")])
    t = _timeline_with_results(r)
    pt = trend_point_from_timeline(t, "v1")
    assert pt.by_severity["high"] == 2
    assert pt.by_severity["low"] == 1


def test_build_trend_report_length():
    t1 = _timeline_with_results(_make_result([_make_match()]))
    t2 = _timeline_with_results(_make_result([_make_match(), _make_match()]))
    report = build_trend_report([t1, t2], ["week1", "week2"])
    assert len(report) == 2


def test_build_trend_report_mismatched_lengths():
    t1 = Timeline()
    with pytest.raises(ValueError):
        build_trend_report([t1], ["a", "b"])


def test_trend_report_as_dict():
    t = _timeline_with_results(_make_result([_make_match()]))
    report = build_trend_report([t], ["run1"])
    d = report.as_dict()
    assert "points" in d
    assert d["points"][0]["label"] == "run1"


def test_format_trend_report_empty():
    report = TrendReport()
    assert "No trend data" in format_trend_report(report)


def test_format_trend_report_contains_label():
    t = _timeline_with_results(_make_result([_make_match()]))
    report = build_trend_report([t], ["sprint-42"])
    out = format_trend_report(report)
    assert "sprint-42" in out


def test_format_trend_report_contains_total():
    r = _make_result([_make_match(), _make_match()])
    t = _timeline_with_results(r)
    report = build_trend_report([t], ["v2"])
    out = format_trend_report(report)
    assert "total=2" in out
