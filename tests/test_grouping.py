import pytest
from hexpose.scanner import Match, ScanResult
from hexpose.grouping import (
    group_by_pattern,
    group_by_severity,
    group_by_offset_range,
    group_result,
    GroupedMatches,
)


def _make_match(pattern_name="aws_key", severity="high", offset=0, value="SECRET"):
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
    )


def _make_result(matches):
    return ScanResult(source="test", matches=matches)


def test_group_by_pattern_empty():
    g = group_by_pattern([])
    assert g.by == "pattern"
    assert g.groups == {}


def test_group_by_pattern_single():
    m = _make_match(pattern_name="jwt")
    g = group_by_pattern([m])
    assert "jwt" in g.keys()
    assert g.get("jwt") == [m]


def test_group_by_pattern_multiple_keys():
    m1 = _make_match(pattern_name="aws_key")
    m2 = _make_match(pattern_name="jwt")
    m3 = _make_match(pattern_name="aws_key")
    g = group_by_pattern([m1, m2, m3])
    assert len(g.get("aws_key")) == 2
    assert len(g.get("jwt")) == 1


def test_group_by_severity():
    m1 = _make_match(severity="critical")
    m2 = _make_match(severity="low")
    m3 = _make_match(severity="critical")
    g = group_by_severity([m1, m2, m3])
    assert g.by == "severity"
    assert len(g.get("critical")) == 2
    assert len(g.get("low")) == 1


def test_group_by_offset_range():
    m1 = _make_match(offset=0)
    m2 = _make_match(offset=100)
    m3 = _make_match(offset=600)
    g = group_by_offset_range([m1, m2, m3], bucket_size=512)
    assert len(g.get("0-511")) == 2
    assert len(g.get("512-1023")) == 1


def test_group_result_by_pattern():
    result = _make_result([_make_match(pattern_name="x"), _make_match(pattern_name="y")])
    g = group_result(result, by="pattern")
    assert set(g.keys()) == {"x", "y"}


def test_group_result_by_severity():
    result = _make_result([_make_match(severity="high"), _make_match(severity="low")])
    g = group_result(result, by="severity")
    assert "high" in g.keys()


def test_group_result_unknown_raises():
    result = _make_result([])
    with pytest.raises(ValueError, match="Unknown grouping"):
        group_result(result, by="unknown")


def test_as_dict_structure():
    m = _make_match(pattern_name="p1", value="VAL")
    g = group_by_pattern([m])
    d = g.as_dict()
    assert d["by"] == "pattern"
    assert "p1" in d["groups"]
    assert d["groups"]["p1"] == ["VAL"]
