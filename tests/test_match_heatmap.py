"""Tests for hexpose.match_heatmap and hexpose.heatmap_report."""
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_heatmap import (
    HeatmapBucket,
    MatchHeatmap,
    build_heatmap,
)
from hexpose.heatmap_report import (
    format_heatmap_report,
    heatmap_summary,
)


def _make_match(pattern_name: str = "aws_key", offset: int = 0, value: str = "AKIA1234") -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity="high")


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test", matches=matches or [])


# --- HeatmapBucket ---

def test_bucket_as_dict_keys():
    b = HeatmapBucket(start=0, end=255, count=3, patterns=["aws_key", "aws_key"])
    d = b.as_dict()
    assert set(d.keys()) == {"start", "end", "count", "patterns"}


def test_bucket_as_dict_deduplicates_patterns():
    b = HeatmapBucket(start=0, end=255, count=2, patterns=["jwt", "jwt", "aws_key"])
    assert b.as_dict()["patterns"] == ["aws_key", "jwt"]


# --- build_heatmap ---

def test_build_heatmap_empty_results():
    heatmap = build_heatmap([])
    assert len(heatmap) == 0


def test_build_heatmap_single_match():
    result = _make_result([_make_match(offset=100)])
    heatmap = build_heatmap([result], bucket_size=256)
    assert len(heatmap) == 1
    bucket = heatmap.buckets[0]
    assert bucket.count == 1
    assert bucket.start == 0
    assert bucket.end == 255


def test_build_heatmap_groups_into_correct_bucket():
    m1 = _make_match(offset=0)
    m2 = _make_match(offset=255)
    m3 = _make_match(offset=256)
    result = _make_result([m1, m2, m3])
    heatmap = build_heatmap([result], bucket_size=256)
    assert len(heatmap) == 2
    assert heatmap.buckets[0].count == 2
    assert heatmap.buckets[1].count == 1


def test_build_heatmap_records_pattern_names():
    m1 = _make_match(pattern_name="jwt", offset=10)
    m2 = _make_match(pattern_name="aws_key", offset=20)
    result = _make_result([m1, m2])
    heatmap = build_heatmap([result], bucket_size=256)
    patterns = heatmap.buckets[0].as_dict()["patterns"]
    assert "jwt" in patterns
    assert "aws_key" in patterns


def test_build_heatmap_invalid_bucket_size_raises():
    with pytest.raises(ValueError):
        build_heatmap([], bucket_size=0)


def test_heatmap_hotspots_returns_top_n():
    matches = [_make_match(offset=i * 256) for i in range(5)]
    # add extra matches to bucket 0 to make it the hotspot
    matches += [_make_match(offset=0) for _ in range(4)]
    result = _make_result(matches)
    heatmap = build_heatmap([result], bucket_size=256)
    hotspots = heatmap.hotspots(top_n=2)
    assert len(hotspots) <= 2
    assert hotspots[0].count >= hotspots[-1].count


def test_heatmap_as_dict_structure():
    result = _make_result([_make_match(offset=50)])
    heatmap = build_heatmap([result], bucket_size=256)
    d = heatmap.as_dict()
    assert d["bucket_size"] == 256
    assert isinstance(d["buckets"], list)


# --- heatmap_report ---

def test_format_heatmap_report_empty():
    heatmap = MatchHeatmap(bucket_size=256)
    report = format_heatmap_report(heatmap)
    assert "No matches" in report


def test_format_heatmap_report_contains_offset():
    result = _make_result([_make_match(offset=0)])
    heatmap = build_heatmap([result], bucket_size=256)
    report = format_heatmap_report(heatmap)
    assert "0x00000000" in report


def test_heatmap_summary_no_data():
    heatmap = MatchHeatmap(bucket_size=256)
    assert "no data" in heatmap_summary(heatmap).lower()


def test_heatmap_summary_contains_hotspot_offset():
    result = _make_result([_make_match(offset=512)])
    heatmap = build_heatmap([result], bucket_size=256)
    summary = heatmap_summary(heatmap)
    assert "0x00000200" in summary
