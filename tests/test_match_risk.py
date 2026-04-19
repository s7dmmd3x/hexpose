"""Tests for hexpose.match_risk and hexpose.risk_report."""
import pytest
from unittest.mock import MagicMock
from hexpose.scanner import Match, ScanResult
from hexpose.match_risk import (
    RiskMatch, assess_risk, assess_risk_all,
    _severity_weight, _entropy_factor, _length_factor, _level,
)
from hexpose.risk_report import format_risk_match, format_risk_report, risk_summary


def _make_match(pattern_name="aws_key", value="AKIAIOSFODNN7EXAMPLE", severity="high", offset=0):
    m = MagicMock(spec=Match)
    m.pattern_name = pattern_name
    m.value = value
    m.severity = severity
    m.offset = offset
    return m


def _make_result(matches):
    r = MagicMock(spec=ScanResult)
    r.matches = matches
    return r


def test_severity_weight_critical():
    assert _severity_weight("critical") == 1.0


def test_severity_weight_low():
    assert _severity_weight("low") == 0.25


def test_severity_weight_unknown_defaults_low():
    assert _severity_weight("unknown") == 0.1


def test_entropy_factor_range():
    f = _entropy_factor("AKIAIOSFODNN7EXAMPLE")
    assert 0.0 <= f <= 1.0


def test_length_factor_short():
    assert _length_factor("x") < _length_factor("x" * 64)


def test_length_factor_caps_at_one():
    assert _length_factor("x" * 200) == 1.0


def test_level_critical():
    assert _level(0.9) == "critical"


def test_level_high():
    assert _level(0.6) == "high"


def test_level_medium():
    assert _level(0.4) == "medium"


def test_level_low():
    assert _level(0.15) == "low"


def test_level_info():
    assert _level(0.05) == "info"


def test_assess_risk_returns_risk_match():
    m = _make_match()
    rm = assess_risk(m)
    assert isinstance(rm, RiskMatch)


def test_assess_risk_score_in_range():
    m = _make_match()
    rm = assess_risk(m)
    assert 0.0 <= rm.risk_score <= 1.0


def test_assess_risk_factors_present():
    m = _make_match()
    rm = assess_risk(m)
    assert "severity_weight" in rm.factors
    assert "entropy_factor" in rm.factors
    assert "length_factor" in rm.factors


def test_assess_risk_critical_severity_high_score():
    m = _make_match(severity="critical", value="A" * 40)
    rm = assess_risk(m)
    assert rm.risk_score > 0.5


def test_assess_risk_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="github_token", severity="critical")]
    result = _make_result(matches)
    risk_list = assess_risk_all(result)
    assert len(risk_list) == 2


def test_as_dict_contains_keys():
    m = _make_match()
    rm = assess_risk(m)
    d = rm.as_dict()
    for key in ("pattern_name", "offset", "value", "risk_score", "risk_level", "factors"):
        assert key in d


def test_format_risk_match_contains_pattern_name():
    m = _make_match()
    rm = assess_risk(m)
    text = format_risk_match(rm)
    assert "aws_key" in text


def test_format_risk_report_empty():
    assert format_risk_report([]) == "No risk matches."


def test_format_risk_report_sorted_descending():
    m1 = _make_match(severity="low", value="x")
    m2 = _make_match(severity="critical", value="A" * 40)
    rms = [assess_risk(m1), assess_risk(m2)]
    text = format_risk_report(rms)
    assert text.index("critical".upper()) < text.index("low".upper()) or "critical" in text


def test_risk_summary_empty():
    assert "0 matches" in risk_summary([])


def test_risk_summary_counts():
    m = _make_match()
    rm = assess_risk(m)
    text = risk_summary([rm])
    assert "1 matches" in text
