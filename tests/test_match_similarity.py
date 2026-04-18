"""Tests for hexpose.match_similarity."""
import pytest
from hexpose.scanner import Match
from hexpose.match_similarity import (
    SimilarMatch,
    find_similar,
    deduplicate_by_similarity,
)


def _make_match(value: str, pattern: str = "aws_key", severity: str = "high") -> Match:
    return Match(pattern_name=pattern, value=value, offset=0, severity=severity)


def test_find_similar_empty():
    assert find_similar([]) == []


def test_find_similar_single_match():
    m = _make_match("AKIAIOSFODNN7EXAMPLE")
    assert find_similar([m]) == []


def test_find_similar_identical_values():
    m1 = _make_match("AKIAIOSFODNN7EXAMPLE")
    m2 = _make_match("AKIAIOSFODNN7EXAMPLE")
    results = find_similar([m1, m2], threshold=0.8)
    assert len(results) == 1
    assert results[0].ratio == pytest.approx(1.0)


def test_find_similar_above_threshold():
    m1 = _make_match("password123")
    m2 = _make_match("password124")
    results = find_similar([m1, m2], threshold=0.8)
    assert len(results) == 1
    assert results[0].ratio > 0.8


def test_find_similar_below_threshold():
    m1 = _make_match("abc")
    m2 = _make_match("xyz")
    results = find_similar([m1, m2], threshold=0.8)
    assert results == []


def test_similar_match_as_dict_keys():
    m1 = _make_match("secretABC")
    m2 = _make_match("secretABD")
    results = find_similar([m1, m2], threshold=0.5)
    assert len(results) == 1
    d = results[0].as_dict()
    assert "pattern_name" in d
    assert "value" in d
    assert "similar_to_value" in d
    assert "ratio" in d


def test_deduplicate_by_similarity_empty():
    assert deduplicate_by_similarity([]) == []


def test_deduplicate_by_similarity_no_duplicates():
    matches = [_make_match("abc"), _make_match("xyz")]
    result = deduplicate_by_similarity(matches, threshold=0.95)
    assert len(result) == 2


def test_deduplicate_by_similarity_removes_near_duplicate():
    m1 = _make_match("AKIAIOSFODNN7EXAMPL1")
    m2 = _make_match("AKIAIOSFODNN7EXAMPL2")
    result = deduplicate_by_similarity([m1, m2], threshold=0.95)
    assert len(result) == 1
    assert result[0] is m1


def test_deduplicate_keeps_distinct_matches():
    matches = [
        _make_match("short"),
        _make_match("completely_different_value_xyz"),
    ]
    result = deduplicate_by_similarity(matches, threshold=0.95)
    assert len(result) == 2
