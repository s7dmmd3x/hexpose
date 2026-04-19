"""Tests for hexpose.match_suppression."""
from datetime import timezone

import pytest

from hexpose.scanner import Match
from hexpose.match_suppression import (
    SuppressedMatch,
    suppress_match,
    suppress_all,
    active_only,
)


def _make_match(pattern_name: str = "aws_key", value: str = "AKIA1234") -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=0, severity="high")


def test_suppress_match_returns_suppressed_match():
    m = _make_match()
    sm = suppress_match(m, reason="false positive", suppressed_by="alice")
    assert isinstance(sm, SuppressedMatch)


def test_suppress_match_suppressed_true_by_default():
    sm = suppress_match(_make_match())
    assert sm.suppressed is True


def test_suppress_match_suppressed_false_when_disabled():
    sm = suppress_match(_make_match(), suppress=False)
    assert sm.suppressed is False


def test_suppress_match_stores_reason():
    sm = suppress_match(_make_match(), reason="  noise  ")
    assert sm.reason == "noise"


def test_suppress_match_stores_suppressed_by():
    sm = suppress_match(_make_match(), suppressed_by="bob")
    assert sm.suppressed_by == "bob"


def test_suppress_match_default_suppressed_by():
    sm = suppress_match(_make_match(), suppressed_by="   ")
    assert sm.suppressed_by == "unknown"


def test_suppress_match_suppressed_at_set_when_suppressed():
    sm = suppress_match(_make_match())
    assert sm.suppressed_at is not None
    assert sm.suppressed_at.tzinfo == timezone.utc


def test_suppress_match_suppressed_at_none_when_not_suppressed():
    sm = suppress_match(_make_match(), suppress=False)
    assert sm.suppressed_at is None


def test_suppress_match_as_dict_keys():
    sm = suppress_match(_make_match(), reason="test", suppressed_by="ci")
    d = sm.as_dict()
    for key in ("pattern_name", "value", "suppressed", "reason", "suppressed_by", "suppressed_at"):
        assert key in d


def test_suppress_match_as_dict_suppressed_at_iso():
    sm = suppress_match(_make_match())
    d = sm.as_dict()
    assert isinstance(d["suppressed_at"], str)
    assert "T" in d["suppressed_at"]


def test_str_suppressed():
    sm = suppress_match(_make_match(), reason="noise")
    assert "suppressed" in str(sm)


def test_str_active():
    sm = suppress_match(_make_match(), suppress=False)
    assert "active" in str(sm)


def test_suppress_all_returns_list():
    matches = [_make_match(), _make_match("github_token", "ghp_abc")]
    result = suppress_all(matches, reason="bulk", suppressed_by="ci")
    assert len(result) == 2
    assert all(isinstance(r, SuppressedMatch) for r in result)


def test_active_only_filters_suppressed():
    matches = [_make_match(), _make_match("jwt", "eyJ")]
    items = suppress_all(matches)
    assert active_only(items) == []


def test_active_only_keeps_non_suppressed():
    m1 = suppress_match(_make_match(), suppress=True)
    m2 = suppress_match(_make_match("jwt", "eyJ"), suppress=False)
    assert active_only([m1, m2]) == [m2]
