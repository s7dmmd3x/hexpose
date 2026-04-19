"""Tests for hexpose.match_expiry."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_expiry import (
    ExpiryMatch,
    apply_expiry,
    apply_expiry_all,
)


def _make_match(pattern_name: str = "aws_key", value: str = "AKIAIOSFODNN7EXAMPLE") -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=0, line=1)


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test", matches=matches or [])


_NOW = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_RECENT = _NOW - timedelta(days=10)
_OLD = _NOW - timedelta(days=100)


def test_apply_expiry_returns_expiry_match():
    em = apply_expiry(_make_match(), _RECENT, max_age_days=90, now=_NOW)
    assert isinstance(em, ExpiryMatch)


def test_apply_expiry_not_expired_when_recent():
    em = apply_expiry(_make_match(), _RECENT, max_age_days=90, now=_NOW)
    assert not em.is_expired


def test_apply_expiry_expired_when_old():
    em = apply_expiry(_make_match(), _OLD, max_age_days=90, now=_NOW)
    assert em.is_expired


def test_apply_expiry_expires_at_correct():
    em = apply_expiry(_make_match(), _RECENT, max_age_days=30, now=_NOW)
    assert em.expires_at == _RECENT + timedelta(days=30)


def test_apply_expiry_stores_max_age_days():
    em = apply_expiry(_make_match(), _RECENT, max_age_days=60, now=_NOW)
    assert em.max_age_days == 60


def test_apply_expiry_boundary_exact_expiry():
    boundary = _RECENT + timedelta(days=90)
    em = apply_expiry(_make_match(), _RECENT, max_age_days=90, now=boundary)
    assert em.is_expired  # now >= expires_at


def test_as_dict_contains_keys():
    em = apply_expiry(_make_match(), _RECENT, max_age_days=90, now=_NOW)
    d = em.as_dict()
    for key in ("pattern_name", "value", "first_seen", "expires_at", "max_age_days", "is_expired"):
        assert key in d


def test_str_expired_label():
    em = apply_expiry(_make_match(), _OLD, max_age_days=90, now=_NOW)
    assert "EXPIRED" in str(em)


def test_str_active_label():
    em = apply_expiry(_make_match(), _RECENT, max_age_days=90, now=_NOW)
    assert "active" in str(em)


def test_apply_expiry_all_returns_list():
    result = _make_result([_make_match(), _make_match("github_token", "ghp_abc")])
    items = apply_expiry_all(result, _RECENT, max_age_days=90, now=_NOW)
    assert len(items) == 2


def test_apply_expiry_all_empty_result():
    result = _make_result([])
    items = apply_expiry_all(result, _RECENT, now=_NOW)
    assert items == []


def test_apply_expiry_all_mixed_expiry():
    result = _make_result([
        _make_match("aws_key"),
        _make_match("github_token"),
    ])
    items_old = apply_expiry_all(result, _OLD, max_age_days=90, now=_NOW)
    assert all(em.is_expired for em in items_old)

    items_new = apply_expiry_all(result, _RECENT, max_age_days=90, now=_NOW)
    assert all(not em.is_expired for em in items_new)
