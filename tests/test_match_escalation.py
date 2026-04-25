"""Tests for hexpose.match_escalation."""
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_escalation import (
    EscalatedMatch,
    escalate_match,
    escalate_result,
    _severity_escalated,
)


def _make_match(
    pattern_name: str = "aws_access_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    severity: str = "high",
    offset: int = 0,
) -> Match:
    return Match(pattern_name=pattern_name, value=value, severity=severity, offset=offset)


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test", matches=matches or [])


# --- _severity_escalated ---

def test_severity_escalated_low_to_high():
    assert _severity_escalated("low", "high") is True


def test_severity_escalated_high_to_low():
    assert _severity_escalated("high", "low") is False


def test_severity_escalated_same_level():
    assert _severity_escalated("medium", "medium") is False


def test_severity_escalated_none_previous():
    assert _severity_escalated(None, "critical") is False


# --- escalate_match ---

def test_escalate_match_returns_escalated_match():
    m = _make_match(severity="critical")
    result = escalate_match(m, baseline_severity="low")
    assert isinstance(result, EscalatedMatch)


def test_escalate_match_escalated_when_severity_increases():
    m = _make_match(severity="critical")
    result = escalate_match(m, baseline_severity="low")
    assert result.escalated is True
    assert "severity increased" in result.reason


def test_escalate_match_not_escalated_when_severity_same():
    m = _make_match(severity="high")
    result = escalate_match(m, baseline_severity="high")
    assert result.escalated is False
    assert result.reason == "no change"


def test_escalate_match_new_finding_flagged():
    m = _make_match(severity="medium")
    result = escalate_match(m, baseline_severity=None, current_count=1)
    assert result.escalated is True
    assert "new finding" in result.reason


def test_escalate_match_count_increase_escalated():
    m = _make_match(severity="low")
    result = escalate_match(m, baseline_severity="low", previous_count=2, current_count=5)
    assert result.escalated is True
    assert "occurrence count increased" in result.reason


def test_escalate_match_stores_severities():
    m = _make_match(severity="high")
    result = escalate_match(m, baseline_severity="medium")
    assert result.previous_severity == "medium"
    assert result.current_severity == "high"


def test_escalate_match_as_dict_contains_keys():
    m = _make_match()
    em = escalate_match(m)
    d = em.as_dict()
    for key in ("pattern_name", "value", "offset", "escalated", "reason",
                "previous_severity", "current_severity", "previous_count", "current_count"):
        assert key in d


def test_escalate_match_str_contains_flag():
    m = _make_match(severity="critical")
    em = escalate_match(m, baseline_severity="low")
    assert "ESCALATED" in str(em)


# --- escalate_result ---

def test_escalate_result_returns_list():
    result = _make_result([_make_match()])
    out = escalate_result(result)
    assert isinstance(out, list)
    assert len(out) == 1


def test_escalate_result_empty_result():
    assert escalate_result(_make_result()) == []


def test_escalate_result_uses_baseline():
    m = _make_match(pattern_name="aws_access_key", severity="critical")
    result = _make_result([m])
    baseline = {"aws_access_key": {"severity": "low", "count": 1}}
    out = escalate_result(result, baseline=baseline)
    assert out[0].escalated is True


def test_escalate_result_no_baseline_new_finding():
    m = _make_match(severity="high")
    result = _make_result([m])
    out = escalate_result(result, baseline={})
    assert out[0].escalated is True
