"""Tests for hexpose.match_impact and hexpose.impact_report."""
import pytest
from unittest.mock import MagicMock
from hexpose.match_impact import assess_impact, assess_impact_all, ImpactedMatch
from hexpose.impact_report import format_impacted_match, format_impact_report, impact_summary


def _make_match(pattern_name="aws_key", value="AKIAIOSFODNN7EXAMPLE", severity="high", offset=0):
    m = MagicMock()
    m.pattern_name = pattern_name
    m.value = value
    m.severity = severity
    m.offset = offset
    return m


def _make_result(matches):
    r = MagicMock()
    r.matches = matches
    return r


def test_assess_impact_returns_impacted_match():
    m = _make_match(severity="high")
    result = assess_impact(m)
    assert isinstance(result, ImpactedMatch)


def test_assess_impact_critical_severity_gives_high_score():
    m = _make_match(severity="critical", value="AKIAIOSFODNN7EXAMPLE")
    result = assess_impact(m)
    assert result.impact_score >= 3.5


def test_assess_impact_low_severity_gives_low_score():
    m = _make_match(severity="low", value="abc")
    result = assess_impact(m)
    assert result.impact_score < 2.0


def test_assess_impact_info_severity():
    m = _make_match(severity="info", value="x")
    result = assess_impact(m)
    assert result.impact_level in {"info", "low"}


def test_assess_impact_rationale_contains_severity():
    m = _make_match(severity="medium")
    result = assess_impact(m)
    assert "severity=medium" in result.rationale


def test_assess_impact_as_dict_keys():
    m = _make_match()
    d = assess_impact(m).as_dict()
    for key in ("pattern_name", "offset", "impact_score", "impact_level", "rationale"):
        assert key in d


def test_assess_impact_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="github_token", severity="critical")]
    result = _make_result(matches)
    items = assess_impact_all(result)
    assert len(items) == 2


def test_assess_impact_all_empty():
    result = _make_result([])
    assert assess_impact_all(result) == []


def test_format_impacted_match_contains_pattern_name():
    m = _make_match(pattern_name="jwt_token")
    im = assess_impact(m)
    text = format_impacted_match(im, color=False)
    assert "jwt_token" in text


def test_format_impacted_match_contains_level():
    m = _make_match(severity="critical", value="AKIAIOSFODNN7EXAMPLE")
    im = assess_impact(m)
    text = format_impacted_match(im, color=False)
    assert im.impact_level.upper() in text


def test_format_impact_report_empty():
    assert format_impact_report([]) == "No impact findings."


def test_format_impact_report_multiple():
    items = [assess_impact(_make_match(severity=s)) for s in ("high", "low")]
    text = format_impact_report(items, color=False)
    assert len(text.splitlines()) == 2


def test_impact_summary_counts_levels():
    items = [assess_impact(_make_match(severity="critical", value="AKIAIOSFODNN7EXAMPLE")) for _ in range(3)]
    summary = impact_summary(items)
    assert "critical" in summary
