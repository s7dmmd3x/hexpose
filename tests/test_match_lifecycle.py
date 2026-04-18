"""Tests for hexpose.match_lifecycle."""
from datetime import datetime, timezone

import pytest

from hexpose.scanner import Match
from hexpose.match_lifecycle import (
    LifecycleMatch,
    open_match,
    resolve_match,
    update_match,
    lifecycle_all,
)

_TS = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_TS2 = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)


def _make_match(name: str = "aws_key", value: str = "AKIAIOSFODNN7EXAMPLE") -> Match:
    return Match(pattern_name=name, value=value, offset=0, severity="high")


def test_open_match_returns_lifecycle_match():
    m = _make_match()
    lm = open_match(m, now=_TS)
    assert isinstance(lm, LifecycleMatch)


def test_open_match_state_is_open():
    lm = open_match(_make_match(), now=_TS)
    assert lm.state == "open"


def test_open_match_timestamps_equal():
    lm = open_match(_make_match(), now=_TS)
    assert lm.created_at == lm.updated_at == _TS


def test_open_match_resolved_at_is_none():
    lm = open_match(_make_match(), now=_TS)
    assert lm.resolved_at is None


def test_resolve_match_state():
    lm = open_match(_make_match(), now=_TS)
    resolved = resolve_match(lm, now=_TS2)
    assert resolved.state == "resolved"


def test_resolve_match_preserves_created_at():
    lm = open_match(_make_match(), now=_TS)
    resolved = resolve_match(lm, now=_TS2)
    assert resolved.created_at == _TS


def test_resolve_match_sets_resolved_at():
    lm = open_match(_make_match(), now=_TS)
    resolved = resolve_match(lm, now=_TS2)
    assert resolved.resolved_at == _TS2


def test_update_match_state():
    lm = open_match(_make_match(), now=_TS)
    new_m = _make_match(value="NEWVALUE")
    updated = update_match(lm, new_m, now=_TS2)
    assert updated.state == "updated"


def test_update_match_replaces_match():
    lm = open_match(_make_match(), now=_TS)
    new_m = _make_match(value="NEWVALUE")
    updated = update_match(lm, new_m, now=_TS2)
    assert updated.match.value == "NEWVALUE"


def test_update_match_preserves_created_at():
    lm = open_match(_make_match(), now=_TS)
    updated = update_match(lm, _make_match(), now=_TS2)
    assert updated.created_at == _TS


def test_lifecycle_all_opens_all_matches():
    matches = [_make_match(), _make_match(name="github_token", value="ghp_abc")]
    items = lifecycle_all(matches, now=_TS)
    assert len(items) == 2
    assert all(lm.state == "open" for lm in items)


def test_as_dict_contains_state():
    lm = open_match(_make_match(), now=_TS)
    d = lm.as_dict()
    assert d["state"] == "open"
    assert d["resolved_at"] is None


def test_as_dict_resolved_at_set_when_resolved():
    lm = resolve_match(open_match(_make_match(), now=_TS), now=_TS2)
    d = lm.as_dict()
    assert d["resolved_at"] is not None
