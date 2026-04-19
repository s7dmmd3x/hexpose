"""Tests for hexpose.match_lineage."""
import pytest
from hexpose.scanner import Match, ScanResult
from hexpose.match_lineage import (
    LineageMatch,
    track_lineage,
    track_lineage_all,
)


def _make_match(pattern_name="aws_key", value="AKIA1234", offset=0, severity="high"):
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
    )


def _make_result(matches=None):
    return ScanResult(source="test", matches=matches or [])


def test_track_lineage_returns_lineage_match():
    m = _make_match()
    lm = track_lineage(m)
    assert isinstance(lm, LineageMatch)
    assert lm.match is m


def test_track_lineage_no_steps():
    lm = track_lineage(_make_match())
    assert lm.steps == []


def test_track_lineage_with_steps():
    lm = track_lineage(_make_match(), "filter", "redact")
    assert lm.steps == ["filter", "redact"]


def test_add_step_chains():
    lm = track_lineage(_make_match())
    result = lm.add("score").add("rank")
    assert result is lm
    assert lm.steps == ["score", "rank"]


def test_add_strips_whitespace():
    lm = track_lineage(_make_match())
    lm.add("  triage  ")
    assert lm.steps == ["triage"]


def test_add_ignores_empty_string():
    lm = track_lineage(_make_match())
    lm.add("")
    lm.add("   ")
    assert lm.steps == []


def test_has_step_true():
    lm = track_lineage(_make_match(), "filter")
    assert lm.has_step("filter") is True


def test_has_step_false():
    lm = track_lineage(_make_match(), "filter")
    assert lm.has_step("score") is False


def test_as_dict_keys():
    lm = track_lineage(_make_match(), "filter")
    d = lm.as_dict()
    assert set(d.keys()) == {"pattern_name", "offset", "value", "severity", "steps"}


def test_as_dict_steps_value():
    lm = track_lineage(_make_match(), "a", "b")
    assert lm.as_dict()["steps"] == ["a", "b"]


def test_str_contains_pattern_name():
    lm = track_lineage(_make_match(pattern_name="jwt"), "filter")
    assert "jwt" in str(lm)


def test_str_contains_steps():
    lm = track_lineage(_make_match(), "filter", "score")
    assert "filter" in str(lm)
    assert "score" in str(lm)


def test_track_lineage_all_empty_result():
    result = _make_result()
    assert track_lineage_all(result) == []


def test_track_lineage_all_returns_one_per_match():
    result = _make_result([_make_match(), _make_match(pattern_name="github_token")])
    lms = track_lineage_all(result, "filter")
    assert len(lms) == 2


def test_track_lineage_all_applies_steps():
    result = _make_result([_make_match()])
    lms = track_lineage_all(result, "redact", "rank")
    assert lms[0].steps == ["redact", "rank"]
