"""Tests for hexpose.narrative_report."""
from __future__ import annotations

from hexpose.scanner import Match
from hexpose.match_narrative import NarrativeMatch, attach_narrative
from hexpose.narrative_report import (
    format_narrative_match,
    format_narrative_report,
    narrative_summary,
)


def _make_nm(
    pattern_name: str = "aws_access_key",
    severity: str = "critical",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    offset: int = 0,
) -> NarrativeMatch:
    m = Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
    )
    return attach_narrative(m)


def test_format_narrative_match_contains_pattern_name():
    nm = _make_nm()
    text = format_narrative_match(nm)
    assert "aws_access_key" in text


def test_format_narrative_match_contains_severity():
    nm = _make_nm(severity="high")
    text = format_narrative_match(nm)
    assert "high" in text


def test_format_narrative_match_contains_narrative():
    nm = _make_nm()
    text = format_narrative_match(nm)
    assert nm.narrative[:30] in text


def test_format_narrative_match_contains_recommendations():
    nm = _make_nm(severity="critical")
    text = format_narrative_match(nm)
    assert "Recommendations" in text


def test_format_narrative_report_empty():
    text = format_narrative_report([])
    assert "No narrative" in text


def test_format_narrative_report_single():
    nm = _make_nm()
    text = format_narrative_report([nm])
    assert "aws_access_key" in text


def test_format_narrative_report_multiple_contains_divider():
    items = [_make_nm(), _make_nm(pattern_name="github_token", severity="high")]
    text = format_narrative_report(items)
    assert "---" in text


def test_narrative_summary_singular():
    nm = _make_nm()
    text = narrative_summary([nm])
    assert "1" in text and "finding" in text


def test_narrative_summary_plural():
    items = [_make_nm(), _make_nm()]
    text = narrative_summary(items)
    assert "2" in text and "findings" in text


def test_narrative_summary_empty():
    text = narrative_summary([])
    assert "0" in text
