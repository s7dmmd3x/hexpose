"""Tests for hexpose.match_correlation."""
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_correlation import (
    CorrelationGroup,
    correlate_by_value,
    correlate_by_pattern,
)


def _make_match(value: str = "secret", pattern: str = "aws_key", offset: int = 0) -> Match:
    return Match(pattern_name=pattern, value=value, offset=offset, severity="high")


def _make_result(*matches: Match) -> ScanResult:
    return ScanResult(source="test", matches=list(matches))


def test_correlate_by_value_empty():
    assert correlate_by_value([]) == {}


def test_correlate_by_value_no_overlap():
    r1 = _make_result(_make_match("aaa"))
    r2 = _make_result(_make_match("bbb"))
    groups = correlate_by_value([r1, r2])
    assert groups == {}


def test_correlate_by_value_finds_shared_value():
    r1 = _make_result(_make_match("shared"))
    r2 = _make_result(_make_match("shared"))
    groups = correlate_by_value([r1, r2])
    assert "shared" in groups
    assert groups["shared"].size == 2


def test_correlate_by_value_labels_sources():
    r1 = _make_result(_make_match("tok"))
    r2 = _make_result(_make_match("tok"))
    groups = correlate_by_value([r1, r2], source_labels=["file_a", "file_b"])
    assert set(groups["tok"].sources) == {"file_a", "file_b"}


def test_correlate_by_value_single_occurrence_excluded():
    r1 = _make_result(_make_match("unique"))
    groups = correlate_by_value([r1])
    assert "unique" not in groups


def test_correlate_by_pattern_returns_all_patterns():
    r1 = _make_result(_make_match(pattern="aws_key"))
    r2 = _make_result(_make_match(pattern="github_token"))
    groups = correlate_by_pattern([r1, r2])
    assert "aws_key" in groups
    assert "github_token" in groups


def test_correlate_by_pattern_groups_same_pattern():
    r1 = _make_result(_make_match("a", pattern="jwt"))
    r2 = _make_result(_make_match("b", pattern="jwt"))
    groups = correlate_by_pattern([r1, r2])
    assert groups["jwt"].size == 2


def test_correlation_group_as_dict_keys():
    g = CorrelationGroup(key="test_key")
    g.add(_make_match("x", "pat"), "src")
    d = g.as_dict()
    assert "key" in d
    assert "match_count" in d
    assert "sources" in d
    assert "pattern_names" in d


def test_correlation_group_deduplicates_sources():
    g = CorrelationGroup(key="k")
    m = _make_match()
    g.add(m, "src1")
    g.add(m, "src1")
    assert g.sources == ["src1"]
