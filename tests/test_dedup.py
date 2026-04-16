"""Tests for hexpose.dedup module."""

from __future__ import annotations

import pytest

from hexpose.dedup import DedupStrategy, dedup_matches, dedup_result
from hexpose.scanner import Match, ScanResult


def _make_match(
    pattern_name: str = "aws_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    offset: int = 0,
    severity: str = "high",
) -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
        context="",
    )


def _make_result(matches: list) -> ScanResult:
    return ScanResult(source="test.bin", matches=matches, metadata={})


# --- dedup_matches ---

def test_dedup_empty_list():
    assert dedup_matches([]) == []


def test_dedup_no_duplicates_unchanged():
    m1 = _make_match(value="AAA", offset=0)
    m2 = _make_match(value="BBB", offset=10)
    result = dedup_matches([m1, m2], strategy=DedupStrategy.VALUE)
    assert result == [m1, m2]


def test_dedup_value_strategy_removes_duplicate():
    m1 = _make_match(value="SECRET", offset=0)
    m2 = _make_match(value="SECRET", offset=50)  # same value, different offset
    result = dedup_matches([m1, m2], strategy=DedupStrategy.VALUE)
    assert len(result) == 1
    assert result[0] is m1


def test_dedup_exact_strategy_keeps_different_offsets():
    m1 = _make_match(value="SECRET", offset=0)
    m2 = _make_match(value="SECRET", offset=50)
    result = dedup_matches([m1, m2], strategy=DedupStrategy.EXACT)
    assert len(result) == 2


def test_dedup_exact_strategy_removes_true_duplicate():
    m1 = _make_match(value="SECRET", offset=0)
    m2 = _make_match(value="SECRET", offset=0)
    result = dedup_matches([m1, m2], strategy=DedupStrategy.EXACT)
    assert len(result) == 1


def test_dedup_fingerprint_strategy_removes_duplicate():
    m1 = _make_match(value="TOKEN", offset=0)
    m2 = _make_match(value="TOKEN", offset=99)
    result = dedup_matches([m1, m2], strategy=DedupStrategy.FINGERPRINT)
    assert len(result) == 1


def test_dedup_preserves_first_seen():
    m1 = _make_match(value="X", offset=0)
    m2 = _make_match(value="X", offset=5)
    result = dedup_matches([m1, m2], strategy=DedupStrategy.VALUE)
    assert result[0] is m1


def test_dedup_different_patterns_not_deduped():
    m1 = _make_match(pattern_name="aws_key", value="SAME")
    m2 = _make_match(pattern_name="github_token", value="SAME")
    result = dedup_matches([m1, m2], strategy=DedupStrategy.VALUE)
    assert len(result) == 2


# --- dedup_result ---

def test_dedup_result_returns_scan_result():
    m1 = _make_match(value="DUP", offset=0)
    m2 = _make_match(value="DUP", offset=10)
    r = _make_result([m1, m2])
    out = dedup_result(r, strategy=DedupStrategy.VALUE)
    assert isinstance(out, ScanResult)
    assert out.source == r.source


def test_dedup_result_deduplicates_matches():
    m1 = _make_match(value="DUP", offset=0)
    m2 = _make_match(value="DUP", offset=10)
    r = _make_result([m1, m2])
    out = dedup_result(r)
    assert len(out.matches) == 1


def test_dedup_result_preserves_metadata():
    r = _make_result([])
    r.metadata["custom"] = "value"
    out = dedup_result(r)
    assert out.metadata["custom"] == "value"


def test_dedup_result_does_not_mutate_original():
    m1 = _make_match(value="DUP", offset=0)
    m2 = _make_match(value="DUP", offset=10)
    r = _make_result([m1, m2])
    dedup_result(r)
    assert len(r.matches) == 2
