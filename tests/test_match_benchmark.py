"""Tests for hexpose.match_benchmark."""
import pytest
from unittest.mock import MagicMock

from hexpose.match_benchmark import (
    BenchmarkMatch,
    _mean_stddev,
    _rating,
    benchmark_match,
    benchmark_all,
)


def _make_match(pattern_name: str = "aws_access_key", offset: int = 0):
    m = MagicMock()
    m.pattern_name = pattern_name
    m.offset = offset
    m.value = "AKIAIOSFODNN7EXAMPLE"
    m.severity = "high"
    return m


# ---------------------------------------------------------------------------
# _mean_stddev
# ---------------------------------------------------------------------------

def test_mean_stddev_empty():
    mean, std = _mean_stddev([])
    assert mean == 0.0
    assert std == 0.0


def test_mean_stddev_single_value():
    mean, std = _mean_stddev([5.0])
    assert mean == 5.0
    assert std == 0.0


def test_mean_stddev_known_values():
    mean, std = _mean_stddev([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
    assert abs(mean - 5.0) < 1e-9
    assert abs(std - 2.0) < 1e-9


# ---------------------------------------------------------------------------
# _rating
# ---------------------------------------------------------------------------

def test_rating_above():
    assert _rating(1.5) == "above"


def test_rating_below():
    assert _rating(-1.5) == "below"


def test_rating_within():
    assert _rating(0.0) == "within"


def test_rating_boundary_above():
    # Exactly at threshold is still "within"
    assert _rating(1.0) == "within"


# ---------------------------------------------------------------------------
# benchmark_match
# ---------------------------------------------------------------------------

def test_benchmark_match_returns_benchmark_match():
    m = _make_match()
    result = benchmark_match(m, 0.8, [0.5, 0.6, 0.55])
    assert isinstance(result, BenchmarkMatch)


def test_benchmark_match_above_baseline():
    historical = [0.3, 0.35, 0.32, 0.31, 0.33]
    bm = benchmark_match(_make_match(), 1.0, historical)
    assert bm.rating == "above"
    assert bm.z_score > 1.0


def test_benchmark_match_within_baseline():
    historical = [0.5, 0.5, 0.5, 0.5]
    bm = benchmark_match(_make_match(), 0.5, historical)
    assert bm.rating == "within"
    assert bm.z_score == 0.0


def test_benchmark_match_zero_stddev_gives_zero_z():
    historical = [0.5, 0.5, 0.5]
    bm = benchmark_match(_make_match(), 0.9, historical)
    assert bm.z_score == 0.0
    assert bm.rating == "within"


def test_benchmark_match_as_dict_keys():
    bm = benchmark_match(_make_match(), 0.7, [0.5, 0.6])
    d = bm.as_dict()
    for key in ("pattern_name", "offset", "score", "baseline_mean", "baseline_stddev", "z_score", "rating"):
        assert key in d


def test_benchmark_match_str_contains_rating():
    bm = benchmark_match(_make_match(), 0.7, [0.5, 0.6])
    assert bm.rating.upper() in str(bm)


# ---------------------------------------------------------------------------
# benchmark_all
# ---------------------------------------------------------------------------

def test_benchmark_all_returns_list_of_correct_length():
    matches = [_make_match() for _ in range(3)]
    scores = [0.4, 0.9, 0.5]
    historical = [0.3, 0.5, 0.45, 0.55]
    results = benchmark_all(matches, scores, historical)
    assert len(results) == 3


def test_benchmark_all_empty_inputs():
    results = benchmark_all([], [], [0.5, 0.6])
    assert results == []
