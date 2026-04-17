"""Tests for hexpose.fingerprint_report."""
from hexpose.scanner import Match
from hexpose.match_fingerprint import fingerprint_match
from hexpose.fingerprint_report import (
    format_fingerprinted_match,
    format_fingerprint_report,
    fingerprint_summary,
)


def _make_fm(pattern_name="aws_key", value="AKIAIOSFODNN7EXAMPLE", offset=0):
    m = Match(pattern_name=pattern_name, value=value, offset=offset, severity="high")
    return fingerprint_match(m)


def test_format_fingerprinted_match_contains_pattern_name():
    fm = _make_fm()
    out = format_fingerprinted_match(fm, color=False)
    assert "aws_key" in out


def test_format_fingerprinted_match_contains_short_fingerprint():
    fm = _make_fm()
    out = format_fingerprinted_match(fm, color=False)
    assert fm.fingerprint[:12] in out


def test_format_fingerprinted_match_contains_offset():
    fm = _make_fm(offset=42)
    out = format_fingerprinted_match(fm, color=False)
    assert "42" in out


def test_format_fingerprint_report_empty():
    out = format_fingerprint_report([], color=False)
    assert "No fingerprinted" in out


def test_format_fingerprint_report_multiple():
    fms = [_make_fm(), _make_fm(pattern_name="github_token", value="ghp_abc")]
    out = format_fingerprint_report(fms, color=False)
    assert "aws_key" in out
    assert "github_token" in out


def test_fingerprint_summary_counts():
    fms = [_make_fm(), _make_fm()]  # same fingerprint
    out = fingerprint_summary(fms)
    assert "2 total" in out
    assert "1 unique" in out
