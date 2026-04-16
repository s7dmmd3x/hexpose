"""Tests for hexpose.timeline."""
import pytest
from datetime import timezone
from hexpose.timeline import (
    TimelineEvent,
    Timeline,
    event_from_result,
    build_timeline,
    format_timeline,
)
from hexpose.scanner import Match, ScanResult


def _make_match(pattern_name="aws_key", value="AKIA1234", offset=0):
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity="high")


def _make_result(source="test.bin", matches=None):
    return ScanResult(source=source, matches=matches or [])


def test_event_from_result_no_matches():
    r = _make_result(matches=[])
    ev = event_from_result(r)
    assert ev.source == "test.bin"
    assert ev.total_matches == 0
    assert ev.pattern_names == []


def test_event_from_result_with_matches():
    r = _make_result(matches=[_make_match("aws_key"), _make_match("github_token")])
    ev = event_from_result(r)
    assert ev.total_matches == 2
    assert "aws_key" in ev.pattern_names
    assert "github_token" in ev.pattern_names


def test_event_from_result_deduplicates_pattern_names():
    r = _make_result(matches=[_make_match("aws_key"), _make_match("aws_key")])
    ev = event_from_result(r)
    assert ev.pattern_names == ["aws_key"]


def test_event_from_result_metadata_passed():
    r = _make_result()
    ev = event_from_result(r, metadata={"run_id": "abc"})
    assert ev.metadata["run_id"] == "abc"


def test_event_timestamp_is_utc():
    r = _make_result()
    ev = event_from_result(r)
    assert ev.timestamp.tzinfo == timezone.utc


def test_event_as_dict_keys():
    r = _make_result(matches=[_make_match()])
    ev = event_from_result(r)
    d = ev.as_dict()
    assert set(d.keys()) == {"timestamp", "source", "total_matches", "pattern_names", "metadata"}


def test_timeline_empty():
    tl = Timeline()
    assert len(tl) == 0
    assert tl.latest() is None


def test_timeline_add_event():
    tl = Timeline()
    ev = event_from_result(_make_result())
    tl.add_event(ev)
    assert len(tl) == 1
    assert tl.latest() is ev


def test_build_timeline_length():
    results = [_make_result(source=f"file{i}.bin") for i in range(3)]
    tl = build_timeline(results)
    assert len(tl) == 3


def test_build_timeline_sources():
    results = [_make_result(source="a.bin"), _make_result(source="b.bin")]
    tl = build_timeline(results)
    sources = [e.source for e in tl.events]
    assert sources == ["a.bin", "b.bin"]


def test_format_timeline_empty():
    tl = Timeline()
    assert format_timeline(tl) == "No timeline events."


def test_format_timeline_contains_source():
    tl = build_timeline([_make_result(source="dump.bin", matches=[_make_match()])])
    out = format_timeline(tl)
    assert "dump.bin" in out


def test_timeline_as_dict():
    tl = build_timeline([_make_result()])
    d = tl.as_dict()
    assert "events" in d
    assert len(d["events"]) == 1
