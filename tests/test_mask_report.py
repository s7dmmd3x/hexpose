"""Tests for hexpose.mask_report."""
from hexpose.scanner import Match
from hexpose.match_mask import mask_match, mask_all
from hexpose.mask_report import format_masked_match, format_mask_report, mask_summary


def _mm(value: str = "AKIAIOSFODNN7EXAMPLE", pattern_name: str = "aws_key", severity: str = "critical"):
    m = Match(pattern_name=pattern_name, value=value, offset=0, severity=severity)
    return mask_match(m, mode="partial")


def test_format_masked_match_contains_pattern_name():
    mm = _mm(pattern_name="github_token")
    out = format_masked_match(mm)
    assert "github_token" in out


def test_format_masked_match_contains_mode():
    mm = _mm()
    out = format_masked_match(mm)
    assert "partial" in out


def test_format_masked_match_contains_severity():
    mm = _mm(severity="high")
    out = format_masked_match(mm)
    assert "HIGH" in out.upper() or "high" in out


def test_format_mask_report_empty():
    out = format_mask_report([])
    assert "No masked" in out


def test_format_mask_report_non_empty():
    mms = [_mm(), _mm(value="anothersecret123", pattern_name="generic_secret")]
    out = format_mask_report(mms)
    assert "aws_key" in out
    assert "generic_secret" in out


def test_mask_summary_counts_correctly():
    mms = [_mm(), _mm()]
    s = mask_summary(mms)
    assert "2" in s


def test_mask_summary_empty():
    s = mask_summary([])
    assert "0" in s
