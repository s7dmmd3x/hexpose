"""Tests for hexpose.match_fingerprint."""
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_fingerprint import (
    _compute_fingerprint,
    fingerprint_match,
    fingerprint_result,
    unique_fingerprints,
    FingerprintedMatch,
)


def _make_match(pattern_name="aws_key", value="AKIAIOSFODNN7EXAMPLE", offset=0) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity="high")


def _make_result(*matches: Match) -> ScanResult:
    return ScanResult(source="test.bin", matches=list(matches))


def test_fingerprint_match_returns_fingerprinted_match():
    m = _make_match()
    fm = fingerprint_match(m)
    assert isinstance(fm, FingerprintedMatch)
    assert fm.match is m
    assert isinstance(fm.fingerprint, str)
    assert len(fm.fingerprint) == 64  # sha256 hex


def test_fingerprint_stable_without_offset():
    m1 = _make_match(offset=0)
    m2 = _make_match(offset=99)
    assert _compute_fingerprint(m1) == _compute_fingerprint(m2)


def test_fingerprint_differs_with_offset():
    m1 = _make_match(offset=0)
    m2 = _make_match(offset=99)
    assert _compute_fingerprint(m1, include_offset=True) != _compute_fingerprint(m2, include_offset=True)


def test_fingerprint_differs_for_different_values():
    m1 = _make_match(value="AAAA")
    m2 = _make_match(value="BBBB")
    assert _compute_fingerprint(m1) != _compute_fingerprint(m2)


def test_fingerprint_differs_for_different_patterns():
    m1 = _make_match(pattern_name="aws_key")
    m2 = _make_match(pattern_name="github_token")
    assert _compute_fingerprint(m1) != _compute_fingerprint(m2)


def test_fingerprint_result_returns_list():
    r = _make_result(_make_match(), _make_match(pattern_name="github_token", value="ghp_abc"))
    fms = fingerprint_result(r)
    assert len(fms) == 2
    assert all(isinstance(fm, FingerprintedMatch) for fm in fms)


def test_fingerprint_result_empty():
    r = _make_result()
    assert fingerprint_result(r) == []


def test_unique_fingerprints_deduplicates():
    m = _make_match()
    r = _make_result(m, _make_match(offset=5))  # same value/pattern, different offset
    fps = unique_fingerprints(r)
    assert len(fps) == 1


def test_unique_fingerprints_sorted():
    r = _make_result(
        _make_match(value="ZZZ"),
        _make_match(value="AAA"),
    )
    fps = unique_fingerprints(r)
    assert fps == sorted(fps)


def test_as_dict_contains_keys():
    m = _make_match()
    fm = fingerprint_match(m)
    d = fm.as_dict()
    assert "fingerprint" in d
    assert "pattern_name" in d
    assert "value" in d
    assert "offset" in d
