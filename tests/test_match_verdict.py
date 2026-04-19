"""Tests for hexpose.match_verdict and hexpose.verdict_report."""
import pytest
from unittest.mock import patch
from hexpose.scanner import Match
from hexpose.match_verdict import (
    assign_verdict,
    assign_verdict_all,
    VerdictMatch,
    VERDICT_CONFIRMED,
    VERDICT_LIKELY,
    VERDICT_UNCERTAIN,
    VERDICT_UNLIKELY,
    _derive_verdict,
)
from hexpose.verdict_report import format_verdict_match, format_verdict_report, verdict_summary


def _make_match(severity="high", value="AKIAIOSFODNN7EXAMPLE", pattern_name="aws_access_key"):
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=0,
        severity=severity,
        line=1,
        context=value,
    )


def test_derive_verdict_confirmed():
    verdict, reason = _derive_verdict(0.85, "critical")
    assert verdict == VERDICT_CONFIRMED


def test_derive_verdict_likely():
    verdict, _ = _derive_verdict(0.60, "low")
    assert verdict == VERDICT_LIKELY


def test_derive_verdict_uncertain():
    verdict, _ = _derive_verdict(0.40, "low")
    assert verdict == VERDICT_UNCERTAIN


def test_derive_verdict_unlikely():
    verdict, _ = _derive_verdict(0.10, "low")
    assert verdict == VERDICT_UNLIKELY


def test_assign_verdict_returns_verdict_match():
    m = _make_match()
    vm = assign_verdict(m)
    assert isinstance(vm, VerdictMatch)
    assert vm.match is m
    assert vm.verdict in (VERDICT_CONFIRMED, VERDICT_LIKELY, VERDICT_UNCERTAIN, VERDICT_UNLIKELY)


def test_assign_verdict_as_dict_keys():
    m = _make_match()
    vm = assign_verdict(m)
    d = vm.as_dict()
    for key in ("pattern_name", "offset", "value", "verdict", "reason", "confidence_score"):
        assert key in d


def test_assign_verdict_all_returns_list():
    matches = [_make_match(), _make_match(severity="low", value="abc")]
    verdicts = assign_verdict_all(matches)
    assert len(verdicts) == 2
    assert all(isinstance(v, VerdictMatch) for v in verdicts)


def test_format_verdict_match_contains_pattern_name():
    m = _make_match()
    vm = assign_verdict(m)
    text = format_verdict_match(vm)
    assert "aws_access_key" in text


def test_format_verdict_match_contains_verdict():
    m = _make_match()
    vm = assign_verdict(m)
    text = format_verdict_match(vm)
    assert vm.verdict.upper() in text


def test_format_verdict_report_empty():
    assert format_verdict_report([]) == "No verdicts to display."


def test_format_verdict_report_non_empty():
    m = _make_match()
    vm = assign_verdict(m)
    report = format_verdict_report([vm])
    assert "Verdict Report" in report


def test_verdict_summary_empty():
    assert verdict_summary([]) == "Verdicts — none"


def test_verdict_summary_counts():
    m = _make_match()
    verdicts = assign_verdict_all([m, m])
    summary = verdict_summary(verdicts)
    assert "Verdicts" in summary
