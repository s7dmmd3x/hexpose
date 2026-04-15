"""Tests for hexpose.filter and hexpose.suppress."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from hexpose.filter import FilterConfig, apply_filter, filter_match, filter_matches
from hexpose.scanner import Match, ScanResult
from hexpose.suppress import SuppressionList, _fingerprint


def _make_match(
    pattern_name="aws_access_key",
    value="AKIAIOSFODNN7EXAMPLE",
    severity="high",
    offset=0,
    entropy=3.5,
) -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
        entropy=entropy,
        context=b"",
    )


# ---------------------------------------------------------------------------
# FilterConfig
# ---------------------------------------------------------------------------

def test_filter_match_no_constraints():
    m = _make_match()
    assert filter_match(m, FilterConfig()) is True


def test_filter_match_min_severity_pass():
    m = _make_match(severity="high")
    assert filter_match(m, FilterConfig(min_severity="medium")) is True


def test_filter_match_min_severity_fail():
    m = _make_match(severity="low")
    assert filter_match(m, FilterConfig(min_severity="high")) is False


def test_filter_match_include_pattern_pass():
    m = _make_match(pattern_name="aws_access_key")
    assert filter_match(m, FilterConfig(include_patterns=["aws_*"])) is True


def test_filter_match_include_pattern_fail():
    m = _make_match(pattern_name="github_token")
    assert filter_match(m, FilterConfig(include_patterns=["aws_*"])) is False


def test_filter_match_exclude_pattern():
    m = _make_match(pattern_name="generic_password")
    assert filter_match(m, FilterConfig(exclude_patterns=["generic_*"])) is False


def test_filter_match_min_entropy_pass():
    m = _make_match(entropy=4.0)
    assert filter_match(m, FilterConfig(min_entropy=3.5)) is True


def test_filter_match_min_entropy_fail():
    m = _make_match(entropy=2.0)
    assert filter_match(m, FilterConfig(min_entropy=3.5)) is False


def test_filter_match_max_offset_fail():
    m = _make_match(offset=1000)
    assert filter_match(m, FilterConfig(max_offset=500)) is False


def test_apply_filter_returns_scan_result():
    matches = [_make_match(severity="low"), _make_match(severity="high")]
    result = ScanResult(source="test.bin", matches=matches)
    filtered = apply_filter(result, FilterConfig(min_severity="high"))
    assert isinstance(filtered, ScanResult)
    assert len(filtered.matches) == 1
    assert filtered.matches[0].severity == "high"


# ---------------------------------------------------------------------------
# SuppressionList
# ---------------------------------------------------------------------------

def test_suppression_add_and_check():
    sl = SuppressionList()
    m = _make_match()
    sl.add(m)
    assert sl.is_suppressed(m) is True


def test_suppression_not_suppressed_by_default():
    sl = SuppressionList()
    assert sl.is_suppressed(_make_match()) is False


def test_suppression_filter():
    sl = SuppressionList()
    m1 = _make_match(value="SECRET1")
    m2 = _make_match(value="SECRET2")
    sl.add(m1)
    kept = sl.filter([m1, m2])
    assert kept == [m2]


def test_suppression_save_and_load():
    sl = SuppressionList()
    m = _make_match()
    sl.add(m)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    sl.save(path)
    sl2 = SuppressionList.load(path)
    assert sl2.is_suppressed(m) is True


def test_suppression_load_missing_file():
    sl = SuppressionList.load("/tmp/nonexistent_hexpose_suppress.json")
    assert len(sl) == 0
