"""Tests for hexpose.match_policy."""
import pytest
from hexpose.scanner import Match
from hexpose.match_policy import (
    Policy,
    PolicyResult,
    evaluate_all,
    failing,
    passing,
)


def _make_match(pattern_name="aws_key", severity="high", value="AKIAIOSFODNN7EXAMPLE") -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=0,
        severity=severity,
    )


def test_policy_result_passed_by_default():
    policy = Policy(name="default")
    m = _make_match()
    result = policy.evaluate(m)
    assert result.passed
    assert result.reasons == []


def test_policy_fails_on_low_severity():
    policy = Policy(name="strict", min_severity=2)  # require high+
    m = _make_match(severity="low")
    result = policy.evaluate(m)
    assert not result.passed
    assert any("severity" in r for r in result.reasons)


def test_policy_passes_exact_min_severity():
    policy = Policy(name="p", min_severity=2)
    m = _make_match(severity="high")
    result = policy.evaluate(m)
    assert result.passed


def test_policy_deny_pattern_fails():
    policy = Policy(name="p", deny_patterns=["aws_key"])
    m = _make_match(pattern_name="aws_key")
    result = policy.evaluate(m)
    assert not result.passed
    assert any("denied" in r for r in result.reasons)


def test_policy_allow_list_rejects_unlisted():
    policy = Policy(name="p", allow_patterns=["github_token"])
    m = _make_match(pattern_name="aws_key")
    result = policy.evaluate(m)
    assert not result.passed


def test_policy_allow_list_accepts_listed():
    policy = Policy(name="p", allow_patterns=["aws_key"])
    m = _make_match(pattern_name="aws_key")
    result = policy.evaluate(m)
    assert result.passed


def test_policy_min_entropy_fails_on_low_entropy():
    policy = Policy(name="p", min_entropy=4.0)
    m = _make_match(value="aaaaaaaaaa")  # near-zero entropy
    result = policy.evaluate(m)
    assert not result.passed
    assert any("entropy" in r for r in result.reasons)


def test_policy_result_as_dict_keys():
    policy = Policy(name="test")
    m = _make_match()
    result = policy.evaluate(m)
    d = result.as_dict()
    assert "policy" in d
    assert "passed" in d
    assert "pattern_name" in d
    assert "severity" in d
    assert "reasons" in d


def test_evaluate_all_returns_one_per_match():
    policy = Policy(name="p")
    matches = [_make_match(), _make_match(pattern_name="jwt")]
    results = evaluate_all(matches, policy)
    assert len(results) == 2


def test_failing_filters_correctly():
    policy = Policy(name="p", min_severity=3)  # require critical
    matches = [_make_match(severity="low"), _make_match(severity="critical", value="x" * 20)]
    results = evaluate_all(matches, policy)
    assert len(failing(results)) == 1
    assert len(passing(results)) == 1
