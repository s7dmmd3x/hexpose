"""Tests for hexpose.match_severity_map."""
import pytest
from hexpose.scanner import Match, ScanResult
from hexpose.match_severity_map import (
    SeverityMapEntry,
    SeverityMap,
    build_severity_map,
    build_severity_map_from_result,
    build_severity_map_from_results,
    remap_severity,
)


def _make_match(pattern_name="aws_key", value="AKIA1234", offset=0, severity="high"):
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


def _make_result(matches):
    return ScanResult(source="test.bin", matches=matches)


def test_build_severity_map_empty():
    sm = build_severity_map([])
    assert sm.keys() == []


def test_build_severity_map_single_match():
    sm = build_severity_map([_make_match(severity="high")])
    entry = sm.get("high")
    assert entry is not None
    assert entry.count == 1
    assert "aws_key" in entry.pattern_names


def test_build_severity_map_groups_by_severity():
    matches = [
        _make_match(severity="high"),
        _make_match(pattern_name="github_token", severity="high"),
        _make_match(pattern_name="jwt", severity="critical"),
    ]
    sm = build_severity_map(matches)
    assert sm.get("high").count == 2
    assert sm.get("critical").count == 1


def test_severity_map_as_dict_structure():
    sm = build_severity_map([_make_match(severity="medium")])
    d = sm.as_dict()
    assert "medium" in d
    assert d["medium"]["count"] == 1
    assert isinstance(d["medium"]["pattern_names"], list)


def test_severity_map_entry_deduplicates_pattern_names():
    matches = [
        _make_match(pattern_name="aws_key", severity="high"),
        _make_match(pattern_name="aws_key", severity="high"),
    ]
    sm = build_severity_map(matches)
    entry = sm.get("high")
    assert entry.as_dict()["pattern_names"] == ["aws_key"]


def test_build_severity_map_from_result():
    result = _make_result([_make_match(severity="low")])
    sm = build_severity_map_from_result(result)
    assert sm.get("low").count == 1


def test_build_severity_map_from_results_merges():
    r1 = _make_result([_make_match(severity="high")])
    r2 = _make_result([_make_match(severity="high"), _make_match(severity="critical")])
    sm = build_severity_map_from_results([r1, r2])
    assert sm.get("high").count == 2
    assert sm.get("critical").count == 1


def test_remap_severity_changes_level():
    matches = [_make_match(severity="low")]
    remapped = remap_severity(matches, {"low": "medium"})
    assert remapped[0].severity == "medium"


def test_remap_severity_leaves_unmapped_unchanged():
    matches = [_make_match(severity="high")]
    remapped = remap_severity(matches, {"low": "medium"})
    assert remapped[0].severity == "high"


def test_remap_severity_does_not_mutate_original():
    matches = [_make_match(severity="low")]
    remap_severity(matches, {"low": "critical"})
    assert matches[0].severity == "low"
