"""Tests for hexpose.lifecycle_report."""
from datetime import datetime, timezone

from hexpose.scanner import Match
from hexpose.match_lifecycle import open_match, resolve_match, lifecycle_all
from hexpose.lifecycle_report import (
    format_lifecycle_match,
    format_lifecycle_report,
    lifecycle_summary,
)

_TS = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_TS2 = datetime(2024, 1, 2, 12, 0, 0, tzinfo=timezone.utc)


def _lm(state: str = "open"):
    m = Match(pattern_name="aws_key", value="AKIAIOSFODNN7EXAMPLE", offset=0, severity="high")
    lm = open_match(m, now=_TS)
    if state == "resolved":
        lm = resolve_match(lm, now=_TS2)
    return lm


def test_format_lifecycle_match_contains_pattern_name():
    assert "aws_key" in format_lifecycle_match(_lm())


def test_format_lifecycle_match_contains_state():
    text = format_lifecycle_match(_lm())
    assert "OPEN" in text


def test_format_lifecycle_match_resolved_contains_resolved():
    text = format_lifecycle_match(_lm("resolved"))
    assert "RESOLVED" in text


def test_format_lifecycle_report_empty():
    assert format_lifecycle_report([]) == "No lifecycle entries."


def test_format_lifecycle_report_multiple():
    items = [_lm(), _lm("resolved")]
    text = format_lifecycle_report(items)
    assert "OPEN" in text
    assert "RESOLVED" in text


def test_lifecycle_summary_counts():
    items = [_lm(), _lm(), _lm("resolved")]
    s = lifecycle_summary(items)
    assert "2 open" in s
    assert "1 resolved" in s


def test_lifecycle_summary_empty():
    assert lifecycle_summary([]) == "Lifecycle: none"
