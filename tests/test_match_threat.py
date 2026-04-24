"""Tests for hexpose.match_threat and hexpose.threat_report."""
import pytest

from hexpose.scanner import Match
from hexpose.match_threat import (
    ThreatMatch,
    _lookup_techniques,
    _threat_level,
    attach_threat,
    attach_threat_all,
)
from hexpose.threat_report import (
    format_threat_match,
    format_threat_report,
    threat_summary,
)


def _make_match(
    pattern_name: str = "aws_access_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    severity: str = "high",
    offset: int = 0,
) -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
        line=1,
    )


# --- _lookup_techniques ---

def test_lookup_techniques_aws():
    result = _lookup_techniques("aws_access_key")
    assert "T1552.005" in result


def test_lookup_techniques_github():
    result = _lookup_techniques("github_token")
    assert "T1552.001" in result


def test_lookup_techniques_unknown_returns_default():
    result = _lookup_techniques("totally_unknown_pattern")
    assert result == ["TA0006"]


def test_lookup_techniques_case_insensitive():
    assert _lookup_techniques("AWS_SECRET") == _lookup_techniques("aws_secret")


# --- _threat_level ---

def test_threat_level_critical():
    assert _threat_level("critical") == "critical"


def test_threat_level_high():
    assert _threat_level("high") == "high"


def test_threat_level_low():
    assert _threat_level("low") == "low"


def test_threat_level_unknown_defaults_medium():
    assert _threat_level("banana") == "medium"


# --- attach_threat ---

def test_attach_threat_returns_threat_match():
    m = _make_match()
    result = attach_threat(m)
    assert isinstance(result, ThreatMatch)


def test_attach_threat_stores_match():
    m = _make_match()
    result = attach_threat(m)
    assert result.match is m


def test_attach_threat_populates_techniques():
    m = _make_match(pattern_name="aws_access_key")
    result = attach_threat(m)
    assert len(result.techniques) > 0


def test_attach_threat_sets_tactic():
    m = _make_match()
    result = attach_threat(m)
    assert result.tactic == "Credential Access"


def test_attach_threat_level_matches_severity():
    m = _make_match(severity="critical")
    result = attach_threat(m)
    assert result.threat_level == "critical"


def test_attach_threat_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="github_token")]
    results = attach_threat_all(matches)
    assert len(results) == 2
    assert all(isinstance(r, ThreatMatch) for r in results)


def test_attach_threat_all_empty():
    assert attach_threat_all([]) == []


def test_as_dict_contains_required_keys():
    m = _make_match()
    tm = attach_threat(m)
    d = tm.as_dict()
    for key in ("pattern_name", "offset", "value", "severity", "techniques", "tactic", "threat_level"):
        assert key in d


# --- threat_report ---

def test_format_threat_match_contains_pattern_name():
    tm = attach_threat(_make_match(pattern_name="aws_access_key"))
    text = format_threat_match(tm)
    assert "aws_access_key" in text


def test_format_threat_match_contains_tactic():
    tm = attach_threat(_make_match())
    text = format_threat_match(tm)
    assert "Credential Access" in text


def test_format_threat_report_empty():
    text = format_threat_report([])
    assert "No threat" in text


def test_format_threat_report_non_empty():
    tms = attach_threat_all([_make_match()])
    text = format_threat_report(tms)
    assert "Threat Intelligence Report" in text


def test_threat_summary_empty():
    assert threat_summary([]) == "threat: 0 findings"


def test_threat_summary_counts_matches():
    tms = attach_threat_all([_make_match(), _make_match(severity="low")])
    summary = threat_summary(tms)
    assert "2 findings" in summary
