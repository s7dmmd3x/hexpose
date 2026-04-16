"""Tests for hexpose.diff_report."""
import pytest
from unittest.mock import patch
from hexpose.scanner import Match
from hexpose.diff_report import DiffReport, build_diff_report, format_diff_report


def _make_match(pattern_name="AWS_KEY", value="AKIAIOSFODNN7EXAMPLE", offset=0) -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity="high",
        context="",
    )


def test_diff_report_has_new_true():
    m = _make_match()
    r = DiffReport(new_matches=[m], resolved_matches=[])
    assert r.has_new is True


def test_diff_report_has_new_false():
    r = DiffReport(new_matches=[], resolved_matches=[])
    assert r.has_new is False


def test_diff_report_has_resolved_true():
    m = _make_match()
    r = DiffReport(new_matches=[], resolved_matches=[m])
    assert r.has_resolved is True


def test_build_diff_report_all_new():
    matches = [_make_match(), _make_match(pattern_name="GITHUB_TOKEN", value="ghp_abc123")]
    report = build_diff_report(matches, baseline_fps=set())
    assert len(report.new_matches) == 2
    assert len(report.resolved_matches) == 0


def test_build_diff_report_known_match_excluded():
    from hexpose.suppress import _fingerprint
    m = _make_match()
    fp = _fingerprint(m)
    report = build_diff_report([m], baseline_fps={fp})
    assert len(report.new_matches) == 0


def test_build_diff_report_mixed():
    from hexpose.suppress import _fingerprint
    m_known = _make_match(value="AKIAIOSFODNN7EXAMPLE")
    m_new = _make_match(value="AKIANEWKEY12345678")
    fp = _fingerprint(m_known)
    report = build_diff_report([m_known, m_new], baseline_fps={fp})
    assert len(report.new_matches) == 1
    assert report.new_matches[0].value == "AKIANEWKEY12345678"


def test_format_diff_report_contains_counts():
    m = _make_match()
    report = DiffReport(new_matches=[m], resolved_matches=[])
    text = format_diff_report(report, color=False)
    assert "New findings   : 1" in text
    assert "Resolved       : 0" in text


def test_format_diff_report_lists_new_match():
    m = _make_match(pattern_name="AWS_KEY", value="AKIAIOSFODNN7EXAMPLE")
    report = DiffReport(new_matches=[m], resolved_matches=[])
    text = format_diff_report(report, color=False)
    assert "AWS_KEY" in text
    assert "AKIAIOSFODNN7EXAMPLE" in text


def test_format_diff_report_no_new_section_when_empty():
    report = DiffReport(new_matches=[], resolved_matches=[])
    text = format_diff_report(report, color=False)
    assert "New findings:" not in text
