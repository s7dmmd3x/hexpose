"""Tests for hexpose/audit_report.py."""
import pytest

from hexpose.scanner import Match
from hexpose.match_audit import audit_match, AuditedMatch
from hexpose.audit_report import (
    format_audited_match,
    format_audit_report,
    audit_summary,
)


def _make_am(pattern_name="aws_access_key", action="created", actor="alice", notes=""):
    m = Match(pattern_name=pattern_name, value="AKIAIOSFODNN7EXAMPLE", severity="high", offset=0)
    return audit_match(m, action=action, actor=actor, notes=notes)


def test_format_audited_match_contains_pattern_name():
    am = _make_am()
    out = format_audited_match(am)
    assert "aws_access_key" in out


def test_format_audited_match_contains_action():
    am = _make_am(action="reviewed")
    out = format_audited_match(am)
    assert "reviewed" in out


def test_format_audited_match_contains_actor():
    am = _make_am(actor="bob")
    out = format_audited_match(am)
    assert "bob" in out


def test_format_audited_match_contains_notes():
    am = _make_am(notes="check this one")
    out = format_audited_match(am)
    assert "check this one" in out


def test_format_audited_match_no_events_message():
    m = Match(pattern_name="jwt", value="eyJ", severity="medium", offset=0)
    am = AuditedMatch(match=m)
    out = format_audited_match(am)
    assert "No audit events" in out


def test_format_audit_report_empty():
    out = format_audit_report([])
    assert "No audited" in out


def test_format_audit_report_multiple():
    audited = [_make_am(), _make_am(pattern_name="github_token", actor="carol")]
    out = format_audit_report(audited)
    assert "aws_access_key" in out
    assert "github_token" in out


def test_audit_summary_counts_matches():
    audited = [_make_am(), _make_am(pattern_name="github_token")]
    s = audit_summary(audited)
    assert "2" in s


def test_audit_summary_counts_events():
    am = _make_am()
    am.add(action="closed", actor="dave")
    s = audit_summary([am])
    assert "2" in s


def test_audit_summary_lists_actors():
    am1 = _make_am(actor="alice")
    am2 = _make_am(actor="bob")
    s = audit_summary([am1, am2])
    assert "alice" in s
    assert "bob" in s


def test_audit_summary_no_actors():
    m = Match(pattern_name="jwt", value="eyJ", severity="medium", offset=0)
    am = AuditedMatch(match=m)
    s = audit_summary([am])
    assert "none" in s
