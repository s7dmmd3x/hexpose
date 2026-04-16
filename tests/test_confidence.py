"""Tests for hexpose.confidence and hexpose.confidence_report."""
import pytest
from unittest.mock import MagicMock
from hexpose.confidence import (
    score_confidence,
    score_confidence_all,
    _level,
    ConfidenceResult,
)
from hexpose.confidence_report import (
    format_confidence_result,
    format_confidence_report,
    confidence_summary,
)


def _make_match(pattern_name="aws_key", value="AKIAIOSFODNN7EXAMPLE", severity="high", offset=0):
    m = MagicMock()
    m.pattern_name = pattern_name
    m.value = value
    m.severity = severity
    m.offset = offset
    return m


def test_level_high():
    assert _level(0.80) == "high"


def test_level_medium():
    assert _level(0.50) == "medium"


def test_level_low():
    assert _level(0.20) == "low"


def test_score_confidence_returns_confidence_result():
    m = _make_match()
    result = score_confidence(m)
    assert isinstance(result, ConfidenceResult)


def test_score_confidence_critical_severity_boosts_score():
    m = _make_match(severity="critical", value="short")
    result = score_confidence(m)
    assert result.score >= 0.40


def test_score_confidence_low_severity_low_score():
    m = _make_match(severity="low", value="abc")
    result = score_confidence(m)
    assert result.score < 0.45


def test_score_confidence_long_value_adds_weight():
    m = _make_match(value="a" * 25, severity="low")
    r_long = score_confidence(m)
    m2 = _make_match(value="ab", severity="low")
    r_short = score_confidence(m2)
    assert r_long.score > r_short.score


def test_score_confidence_reasons_not_empty():
    m = _make_match()
    result = score_confidence(m)
    assert len(result.reasons) > 0


def test_score_capped_at_one():
    m = _make_match(severity="critical", value="AKIAIOSFODNN7EXAMPLE_EXTRA_LONG_VALUE_HERE")
    result = score_confidence(m)
    assert result.score <= 1.0


def test_score_confidence_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="github_token", value="ghp_abc123")]
    results = score_confidence_all(matches)
    assert len(results) == 2


def test_as_dict_keys():
    m = _make_match()
    d = score_confidence(m).as_dict()
    assert "score" in d and "level" in d and "reasons" in d


def test_format_confidence_result_contains_pattern_name():
    m = _make_match()
    cr = score_confidence(m)
    text = format_confidence_result(cr, color=False)
    assert "aws_key" in text


def test_format_confidence_result_contains_score():
    m = _make_match()
    cr = score_confidence(m)
    text = format_confidence_result(cr, color=False)
    assert "score=" in text


def test_format_confidence_report_empty():
    assert format_confidence_report([], color=False) == "No matches to report."


def test_confidence_summary_counts():
    matches = [_make_match(severity="critical"), _make_match(severity="low", value="x")]
    results = score_confidence_all(matches)
    summary = confidence_summary(results)
    assert summary["total"] == 2
    assert sum(summary["by_level"].values()) == 2
