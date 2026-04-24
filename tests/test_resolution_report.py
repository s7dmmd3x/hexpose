"""Tests for hexpose.resolution_report."""
from __future__ import annotations

from hexpose.scanner import Match
from hexpose.match_resolution import resolve_match
from hexpose.resolution_report import (
    format_resolution_match,
    format_resolution_report,
    resolution_summary,
)


def _make_rm(resolution: str = "open", resolved_by: str = None, notes=None):
    m = Match(pattern_name="aws_key", value="AKIAIOSFODNN7EXAMPLE", offset=0, severity="critical")
    return resolve_match(m, resolution=resolution, resolved_by=resolved_by, notes=notes)


def test_format_resolution_match_contains_pattern_name():
    rm = _make_rm(resolution="fixed")
    out = format_resolution_match(rm, colour=False)
    assert "aws_key" in out


def test_format_resolution_match_contains_resolution_tag():
    rm = _make_rm(resolution="wont_fix")
    out = format_resolution_match(rm, colour=False)
    assert "WONT_FIX" in out


def test_format_resolution_match_contains_resolved_by():
    rm = _make_rm(resolution="fixed", resolved_by="carol")
    out = format_resolution_match(rm, colour=False)
    assert "carol" in out


def test_format_resolution_match_contains_notes():
    rm = _make_rm(resolution="fixed", notes=["rotated", "verified"])
    out = format_resolution_match(rm, colour=False)
    assert "rotated" in out
    assert "verified" in out


def test_format_resolution_report_empty():
    out = format_resolution_report([], colour=False)
    assert "No resolution records" in out


def test_format_resolution_report_multiple():
    items = [_make_rm("fixed"), _make_rm("open")]
    out = format_resolution_report(items, colour=False)
    assert "FIXED" in out
    assert "OPEN" in out


def test_resolution_summary_empty():
    out = resolution_summary([])
    assert "No records" in out


def test_resolution_summary_counts_resolutions():
    items = [_make_rm("fixed"), _make_rm("fixed"), _make_rm("open")]
    out = resolution_summary(items)
    assert "fixed: 2" in out
    assert "open: 1" in out
    assert "3 total" in out
