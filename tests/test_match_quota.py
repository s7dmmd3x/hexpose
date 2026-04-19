"""Tests for hexpose.match_quota."""
import pytest
from hexpose.scanner import Match, ScanResult
from hexpose.match_quota import QuotaConfig, QuotaResult, apply_quota, apply_quota_to_result


def _make_match(pattern_name: str = "aws_key", value: str = "AKIA1234") -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=0,
        severity="high",
        context="",
    )


def _make_result(matches):
    return ScanResult(source="test", matches=matches)


def test_apply_quota_no_limits_keeps_all():
    matches = [_make_match() for _ in range(10)]
    qr = apply_quota(matches, QuotaConfig())
    assert len(qr.matches) == 10
    assert qr.dropped == 0
    assert not qr.capped


def test_apply_quota_max_total_caps():
    matches = [_make_match() for _ in range(10)]
    qr = apply_quota(matches, QuotaConfig(max_total=3))
    assert len(qr.matches) == 3
    assert qr.dropped == 7
    assert qr.capped


def test_apply_quota_max_per_pattern():
    matches = [_make_match("aws_key") for _ in range(5)] + \
              [_make_match("github_token") for _ in range(5)]
    qr = apply_quota(matches, QuotaConfig(max_per_pattern=2))
    assert len(qr.matches) == 4
    assert qr.dropped == 6
    assert not qr.capped


def test_apply_quota_per_pattern_override():
    matches = [_make_match("aws_key") for _ in range(5)]
    config = QuotaConfig(max_per_pattern=1, per_pattern_overrides={"aws_key": 3})
    qr = apply_quota(matches, config)
    assert len(qr.matches) == 3


def test_apply_quota_combined_limits():
    matches = [_make_match("aws_key") for _ in range(4)] + \
              [_make_match("github_token") for _ in range(4)]
    qr = apply_quota(matches, QuotaConfig(max_per_pattern=3, max_total=5))
    assert len(qr.matches) == 5
    assert qr.capped


def test_quota_result_as_dict():
    qr = QuotaResult(matches=[], dropped=2, capped=True)
    d = qr.as_dict()
    assert d["dropped"] == 2
    assert d["capped"] is True
    assert d["match_count"] == 0


def test_apply_quota_to_result():
    result = _make_result([_make_match() for _ in range(6)])
    qr = apply_quota_to_result(result, QuotaConfig(max_total=4))
    assert len(qr.matches) == 4


def test_apply_quota_empty_input():
    qr = apply_quota([], QuotaConfig(max_total=5, max_per_pattern=2))
    assert qr.matches == []
    assert qr.dropped == 0
    assert not qr.capped
