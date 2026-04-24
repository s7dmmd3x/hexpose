"""Tests for hexpose.match_anomaly."""
import pytest
from hexpose.scanner import Match, ScanResult
from hexpose.match_anomaly import (
    AnomalyMatch,
    detect_anomalies,
    detect_anomalies_in_result,
)


def _make_match(value: str, pattern_name: str = "test_pattern", severity: str = "medium") -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=0, severity=severity)


def _make_result(matches):
    return ScanResult(source="test", matches=list(matches))


def test_detect_anomalies_empty_returns_empty():
    assert detect_anomalies([]) == []


def test_detect_anomalies_returns_anomaly_match_instances():
    matches = [_make_match("abc"), _make_match("xyz")]
    results = detect_anomalies(matches)
    assert all(isinstance(r, AnomalyMatch) for r in results)


def test_detect_anomalies_length_matches_input():
    matches = [_make_match(v) for v in ["aaa", "bbb", "ccc"]]
    results = detect_anomalies(matches)
    assert len(results) == 3


def test_detect_anomalies_single_match_z_score_is_zero():
    results = detect_anomalies([_make_match("AKIAIOSFODNN7EXAMPLE")])
    assert results[0].z_score == 0.0


def test_detect_anomalies_single_match_not_anomaly():
    results = detect_anomalies([_make_match("AKIAIOSFODNN7EXAMPLE")])
    assert results[0].is_anomaly is False


def test_detect_anomalies_uniform_values_all_z_zero():
    # Identical values have zero stddev => all z=0
    matches = [_make_match("aaaa") for _ in range(5)]
    results = detect_anomalies(matches)
    assert all(r.z_score == 0.0 for r in results)


def test_detect_anomalies_high_entropy_value_flagged():
    # Mix low-entropy values with one high-entropy outlier
    low = [_make_match("aaaa") for _ in range(8)]
    high = [_make_match("A3f!9zQw")]  # higher entropy
    results = detect_anomalies(low + high, threshold=1.5)
    anomalies = [r for r in results if r.is_anomaly]
    assert len(anomalies) >= 1


def test_detect_anomalies_threshold_respected():
    low = [_make_match("aaaa") for _ in range(8)]
    high = [_make_match("A3f!9zQw")]
    # Very high threshold means nothing is an anomaly
    results = detect_anomalies(low + high, threshold=100.0)
    assert all(not r.is_anomaly for r in results)


def test_detect_anomalies_mean_entropy_same_for_all():
    matches = [_make_match(v) for v in ["abc", "def", "ghi"]]
    results = detect_anomalies(matches)
    means = {r.mean_entropy for r in results}
    assert len(means) == 1


def test_anomaly_match_as_dict_contains_required_keys():
    results = detect_anomalies([_make_match("secret123")])
    d = results[0].as_dict()
    for key in ("pattern_name", "value", "z_score", "is_anomaly", "mean_entropy", "stddev_entropy", "notes"):
        assert key in d


def test_anomaly_match_str_contains_pattern_name():
    results = detect_anomalies([_make_match("abc", pattern_name="aws_key")])
    assert "aws_key" in str(results[0])


def test_anomaly_match_str_anomaly_flag():
    low = [_make_match("aaaa") for _ in range(8)]
    high = [_make_match("A3f!9zQw")]
    results = detect_anomalies(low + high, threshold=1.5)
    anomalous = [r for r in results if r.is_anomaly][0]
    assert "[ANOMALY]" in str(anomalous)


def test_anomaly_match_str_normal_flag():
    results = detect_anomalies([_make_match("aaaa") for _ in range(3)])
    assert "[normal]" in str(results[0])


def test_detect_anomalies_in_result_empty():
    result = _make_result([])
    assert detect_anomalies_in_result(result) == []


def test_detect_anomalies_in_result_delegates_correctly():
    matches = [_make_match(v) for v in ["abc", "xyz", "123"]]
    result = _make_result(matches)
    direct = detect_anomalies(matches)
    via_result = detect_anomalies_in_result(result)
    assert len(direct) == len(via_result)
    for a, b in zip(direct, via_result):
        assert a.z_score == pytest.approx(b.z_score)
