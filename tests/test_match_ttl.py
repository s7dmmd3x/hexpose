"""Tests for hexpose.match_ttl."""
from datetime import datetime, timedelta, timezone

import pytest

from hexpose.scanner import Match
from hexpose.match_ttl import (
    TTLMatch,
    apply_ttl,
    apply_ttl_all,
    active_matches,
    expired_matches,
)


def _make_match(pattern_name: str = "aws_key", value: str = "AKIA1234") -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=0,
        severity="high",
        line="AKIA1234",
    )


REF = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_apply_ttl_returns_ttl_match():
    m = _make_match()
    result = apply_ttl(m, ttl_days=30, reference=REF)
    assert isinstance(result, TTLMatch)


def test_apply_ttl_not_expired_when_fresh():
    m = _make_match()
    # first_seen is same as reference -> not yet expired
    m.first_seen = REF
    result = apply_ttl(m, ttl_days=30, reference=REF)
    assert result.expired is False


def test_apply_ttl_expired_when_old():
    m = _make_match()
    m.first_seen = REF - timedelta(days=31)
    result = apply_ttl(m, ttl_days=30, reference=REF)
    assert result.expired is True


def test_apply_ttl_expires_at_correct():
    m = _make_match()
    m.first_seen = REF
    result = apply_ttl(m, ttl_days=10, reference=REF)
    expected = REF + timedelta(days=10)
    assert result.expires_at == expected


def test_apply_ttl_no_first_seen_uses_reference():
    m = _make_match()
    # no first_seen attribute set
    result = apply_ttl(m, ttl_days=5, reference=REF)
    # expires_at = REF + 5 days; reference == first_seen so not expired
    assert result.expired is False
    assert result.expires_at == REF + timedelta(days=5)


def test_apply_ttl_all_returns_list():
    matches = [_make_match(), _make_match("github_token", "ghp_abc")]
    results = apply_ttl_all(matches, ttl_days=30, reference=REF)
    assert len(results) == 2
    assert all(isinstance(r, TTLMatch) for r in results)


def test_active_matches_filters_expired():
    m1 = _make_match()
    m1.first_seen = REF - timedelta(days=31)
    m2 = _make_match()
    m2.first_seen = REF
    ttls = apply_ttl_all([m1, m2], ttl_days=30, reference=REF)
    active = active_matches(ttls)
    assert len(active) == 1
    assert active[0].expired is False


def test_expired_matches_filters_active():
    m1 = _make_match()
    m1.first_seen = REF - timedelta(days=31)
    m2 = _make_match()
    m2.first_seen = REF
    ttls = apply_ttl_all([m1, m2], ttl_days=30, reference=REF)
    exp = expired_matches(ttls)
    assert len(exp) == 1
    assert exp[0].expired is True


def test_as_dict_contains_keys():
    m = _make_match()
    m.first_seen = REF
    result = apply_ttl(m, ttl_days=7, reference=REF)
    d = result.as_dict()
    assert "pattern_name" in d
    assert "expires_at" in d
    assert "expired" in d


def test_str_shows_active():
    m = _make_match()
    m.first_seen = REF
    result = apply_ttl(m, ttl_days=30, reference=REF)
    assert "ACTIVE" in str(result)


def test_str_shows_expired():
    m = _make_match()
    m.first_seen = REF - timedelta(days=31)
    result = apply_ttl(m, ttl_days=30, reference=REF)
    assert "EXPIRED" in str(result)
