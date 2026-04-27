"""Tests for hexpose/match_audit.py."""
import pytest
from unittest.mock import patch
from datetime import datetime, timezone

from hexpose.scanner import Match
from hexpose.match_audit import (
    AuditEvent,
    AuditedMatch,
    audit_match,
    audit_all,
)


def _make_match(pattern_name="aws_access_key", value="AKIAIOSFODNN7EXAMPLE", severity="high", offset=0):
    return Match(pattern_name=pattern_name, value=value, severity=severity, offset=offset)


def test_audit_match_returns_audited_match():
    m = _make_match()
    am = audit_match(m, action="created", actor="alice")
    assert isinstance(am, AuditedMatch)


def test_audit_match_records_first_event():
    m = _make_match()
    am = audit_match(m, action="created", actor="alice")
    assert len(am.events) == 1
    assert am.events[0].action == "created"
    assert am.events[0].actor == "alice"


def test_audit_match_stores_notes():
    m = _make_match()
    am = audit_match(m, action="reviewed", actor="bob", notes="looks suspicious")
    assert am.events[0].notes == "looks suspicious"


def test_add_appends_event():
    m = _make_match()
    am = audit_match(m, action="created", actor="alice")
    am.add(action="reviewed", actor="bob")
    assert len(am.events) == 2
    assert am.events[1].action == "reviewed"


def test_add_strips_whitespace():
    m = _make_match()
    am = AuditedMatch(match=m)
    am.add(action="  flagged  ", actor="  carol  ")
    assert am.events[0].action == "flagged"
    assert am.events[0].actor == "carol"


def test_last_event_returns_none_when_empty():
    m = _make_match()
    am = AuditedMatch(match=m)
    assert am.last_event() is None


def test_last_event_returns_most_recent():
    m = _make_match()
    am = audit_match(m, action="created", actor="alice")
    am.add(action="closed", actor="bob")
    assert am.last_event().action == "closed"


def test_has_action_true():
    m = _make_match()
    am = audit_match(m, action="reviewed", actor="alice")
    assert am.has_action("reviewed") is True


def test_has_action_false():
    m = _make_match()
    am = audit_match(m, action="created", actor="alice")
    assert am.has_action("closed") is False


def test_as_dict_contains_required_keys():
    m = _make_match()
    am = audit_match(m, action="created", actor="alice")
    d = am.as_dict()
    for key in ("pattern_name", "offset", "value", "severity", "events"):
        assert key in d


def test_as_dict_events_list():
    m = _make_match()
    am = audit_match(m, action="created", actor="alice")
    d = am.as_dict()
    assert isinstance(d["events"], list)
    assert d["events"][0]["action"] == "created"


def test_audit_event_as_dict_keys():
    ev = AuditEvent(action="test", actor="x", timestamp=datetime.now(timezone.utc))
    d = ev.as_dict()
    for key in ("action", "actor", "timestamp", "notes"):
        assert key in d


def test_audit_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="github_token", value="ghp_abc")]
    result = audit_all(matches, action="imported", actor="system")
    assert len(result) == 2
    assert all(isinstance(r, AuditedMatch) for r in result)


def test_audit_all_empty_input():
    result = audit_all([], action="imported", actor="system")
    assert result == []


def test_str_representation():
    m = _make_match()
    am = audit_match(m, action="created", actor="alice")
    s = str(am)
    assert "AuditedMatch" in s
    assert "aws_access_key" in s
