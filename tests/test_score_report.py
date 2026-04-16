"""Tests for hexpose.score_report."""
from unittest.mock import MagicMock
from hexpose.scoring import ScoredMatch
from hexpose.score_report import format_scored_match, format_score_report, score_summary


def _make_sm(grade="HIGH", final=70.0, name="aws_key", value="AKIA..."):
    match = MagicMock()
    match.pattern_name = name
    match.value = value
    return ScoredMatch(
        match=match,
        base_score=60.0,
        entropy_bonus=5.0,
        watchlist_bonus=5.0,
        final_score=final,
        grade=grade,
    )


def test_format_scored_match_contains_grade():
    sm = _make_sm(grade="HIGH")
    out = format_scored_match(sm, color=False)
    assert "HIGH" in out


def test_format_scored_match_contains_pattern_name():
    sm = _make_sm(name="github_token")
    out = format_scored_match(sm, color=False)
    assert "github_token" in out


def test_format_scored_match_contains_score():
    sm = _make_sm(final=72.5)
    out = format_scored_match(sm, color=False)
    assert "72.5" in out


def test_format_score_report_empty():
    assert format_score_report([]) == "No scored matches."


def test_format_score_report_sorted_descending():
    low = _make_sm(grade="LOW", final=20.0)
    high = _make_sm(grade="HIGH", final=75.0)
    out = format_score_report([low, high], color=False)
    assert out.index("75.0") < out.index("20.0")


def test_format_score_report_header():
    sm = _make_sm()
    out = format_score_report([sm], color=False)
    assert "Scored matches" in out


def test_score_summary_counts():
    sms = [_make_sm("HIGH"), _make_sm("HIGH"), _make_sm("CRITICAL")]
    summary = score_summary(sms)
    assert summary["HIGH"] == 2
    assert summary["CRITICAL"] == 1


def test_score_summary_empty():
    assert score_summary([]) == {}
