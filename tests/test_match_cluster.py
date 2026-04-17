"""Tests for hexpose.match_cluster."""
import pytest
from hexpose.scanner import Match
from hexpose.match_cluster import (
    MatchCluster,
    cluster_by_pattern,
    cluster_by_proximity,
    largest_cluster,
)


def _make_match(pattern_name: str = "aws_key", value: str = "AKIA1234", offset: int = 0, severity: str = "high") -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


def test_cluster_by_pattern_empty():
    assert cluster_by_pattern([]) == {}


def test_cluster_by_pattern_single():
    m = _make_match("aws_key")
    result = cluster_by_pattern([m])
    assert "aws_key" in result
    assert result["aws_key"].size() == 1


def test_cluster_by_pattern_groups_correctly():
    matches = [_make_match("aws_key"), _make_match("aws_key"), _make_match("github_token")]
    result = cluster_by_pattern(matches)
    assert result["aws_key"].size() == 2
    assert result["github_token"].size() == 1


def test_cluster_as_dict_keys():
    m = _make_match("aws_key", offset=10)
    cluster = MatchCluster(key="aws_key")
    cluster.add(m)
    d = cluster.as_dict()
    assert d["key"] == "aws_key"
    assert d["count"] == 1
    assert isinstance(d["matches"], list)
    assert d["matches"][0]["offset"] == 10


def test_cluster_by_proximity_empty():
    assert cluster_by_proximity([]) == []


def test_cluster_by_proximity_single():
    m = _make_match(offset=0)
    result = cluster_by_proximity([m])
    assert len(result) == 1
    assert result[0].size() == 1


def test_cluster_by_proximity_groups_close_matches():
    matches = [_make_match(offset=0), _make_match(offset=100), _make_match(offset=200)]
    result = cluster_by_proximity(matches, window=256)
    assert len(result) == 1
    assert result[0].size() == 3


def test_cluster_by_proximity_splits_distant_matches():
    matches = [_make_match(offset=0), _make_match(offset=1000)]
    result = cluster_by_proximity(matches, window=256)
    assert len(result) == 2


def test_largest_cluster_none_on_empty():
    assert largest_cluster({}) is None


def test_largest_cluster_returns_biggest():
    m1 = _make_match("aws_key")
    m2 = _make_match("aws_key")
    m3 = _make_match("github_token")
    clusters = cluster_by_pattern([m1, m2, m3])
    biggest = largest_cluster(clusters)
    assert biggest is not None
    assert biggest.key == "aws_key"
    assert biggest.size() == 2
