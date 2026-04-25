"""Tests for hexpose.escalation_report."""
import pytest

from hexpose.scanner import Match
from hexpose.match_escalation import EscalatedMatch, escalate_match
from hexpose.escalation_report import (
    format_escalated_match,
    format_escalation_report,
    escalation_summary,
)


def _make_em(
    pattern_name: str = "aws_access_key",
    severity: str = "high",
    previous_severity: str = "low",
    escalated: bool = True,
    reason: str = "severity increased",
) -> EscalatedMatch:
    m = Match(pattern_name=pattern_name, value="AKIAIOSFODNN7EXAMPLE",
              severity=severity, offset=0)
    return EscalatedMatch(
        match=m,
        previous_severity=previous_severity,
        current_severity=severity,
        escalated=escalated,
        reason=reason,
    )


def test_format_escalated_match_contains_pattern_name():
    em = _make_em()
    out = format_escalated_match(em, color=False)
    assert "aws_access_key" in out


def test_format_escalated_match_contains_escalated_flag():
    em = _make_em(escalated=True)
    out = format_escalated_match(em, color=False)
    assert "ESCALATED" in out


def test_format_escalated_match_stable_flag():
    em = _make_em(escalated=False, reason="no change")
    out = format_escalated_match(em, color=False)
    assert "stable" in out


def test_format_escalated_match_contains_reason():
    em = _make_em(reason="severity increased")
    out = format_escalated_match(em, color=False)
    assert "severity increased" in out


def test_format_escalation_report_empty():
    out = format_escalation_report([], color=False)
    assert "No matches" in out


def test_format_escalation_report_no_escalations_only_filter():
    em = _make_em(escalated=False, reason="no change")
    out = format_escalation_report([em], color=False, only_escalated=True)
    assert "No escalations" in out


def test_format_escalation_report_contains_header():
    em = _make_em()
    out = format_escalation_report([em], color=False)
    assert "Escalation Report" in out


def test_escalation_summary_correct_counts():
    ems = [_make_em(escalated=True), _make_em(escalated=False, reason="no change")]
    out = escalation_summary(ems)
    assert "1/2" in out
