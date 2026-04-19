"""Tests for hexpose.match_frequency."""
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_frequency import (
    FrequencyRecord,
    FrequencyReport,
    build_frequency_report,
    pattern_frequency,
)


def _make_match(pattern_name: str, value: str = "secret") -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=0,
        severity="high",
        line="line",
    )


def _make_result(*pattern_names: str) -> ScanResult:
    return ScanResult(
        source="test",
        matches=[_make_match(n) for n in pattern_names],
    )


def test_build_frequency_report_empty():
    report = build_frequency_report([])
    assert len(report) == 0
    assert report.records == []


def test_build_frequency_report_single_result():
    result = _make_result("aws_key", "aws_key", "github_token")
    report = build_frequency_report([result])
    counts = {r.pattern_name: r.count for r in report.records}
    assert counts["aws_key"] == 2
    assert counts["github_token"] == 1


def test_build_frequency_report_multiple_results():
    r1 = _make_result("aws_key")
    r2 = _make_result("aws_key", "jwt")
    report = build_frequency_report([r1, r2])
    counts = {r.pattern_name: r.count for r in report.records}
    assert counts["aws_key"] == 2
    assert counts["jwt"] == 1


def test_results_seen_counts_distinct_results():
    r1 = _make_result("aws_key", "aws_key")
    r2 = _make_result("aws_key")
    report = build_frequency_report([r1, r2])
    rec = next(r for r in report.records if r.pattern_name == "aws_key")
    assert rec.results_seen == 2


def test_results_seen_only_one_result():
    r1 = _make_result("aws_key", "aws_key")
    report = build_frequency_report([r1])
    rec = report.records[0]
    assert rec.results_seen == 1


def test_report_sorted_descending():
    result = _make_result("a", "b", "b", "b", "a")
    report = build_frequency_report([result])
    counts = [r.count for r in report.records]
    assert counts == sorted(counts, reverse=True)


def test_top_n_returns_at_most_n():
    result = _make_result("a", "b", "c", "d", "e", "f")
    report = build_frequency_report([result])
    assert len(report.top(3)) == 3


def test_top_n_larger_than_records():
    result = _make_result("a", "b")
    report = build_frequency_report([result])
    assert len(report.top(10)) == 2


def test_pattern_frequency_returns_dict():
    result = _make_result("aws_key", "jwt")
    freq = pattern_frequency([result])
    assert isinstance(freq, dict)
    assert freq["aws_key"] == 1
    assert freq["jwt"] == 1


def test_frequency_record_as_dict_keys():
    rec = FrequencyRecord(pattern_name="aws_key", count=3, results_seen=2)
    d = rec.as_dict()
    assert "pattern_name" in d
    assert "count" in d
    assert "results_seen" in d


def test_frequency_report_as_dict():
    result = _make_result("aws_key")
    report = build_frequency_report([result])
    d = report.as_dict()
    assert "records" in d
    assert isinstance(d["records"], list)
