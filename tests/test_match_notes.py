"""Tests for hexpose.match_notes."""
import pytest
from hexpose.scanner import Match
from hexpose.match_notes import NotedMatch, note_match, annotate_result


def _make_match(pattern_name="aws_key", value="AKIA1234", offset=0) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity="high")


def test_note_match_returns_noted_match():
    m = _make_match()
    nm = note_match(m, "review this", "possible test key")
    assert isinstance(nm, NotedMatch)
    assert nm.match is m
    assert len(nm.notes) == 2


def test_note_match_no_notes():
    m = _make_match()
    nm = note_match(m)
    assert not nm.has_notes()


def test_add_strips_whitespace():
    m = _make_match()
    nm = NotedMatch(match=m)
    nm.add("  hello  ")
    assert nm.notes == ["hello"]


def test_add_ignores_empty_string():
    m = _make_match()
    nm = NotedMatch(match=m)
    nm.add("")
    nm.add("   ")
    assert nm.notes == []


def test_has_notes_true():
    m = _make_match()
    nm = note_match(m, "important")
    assert nm.has_notes()


def test_as_dict_structure():
    m = _make_match()
    nm = note_match(m, "check me")
    d = nm.as_dict()
    assert d["pattern_name"] == "aws_key"
    assert d["value"] == "AKIA1234"
    assert d["notes"] == ["check me"]
    assert "offset" in d


def test_annotate_result_maps_by_pattern():
    m1 = _make_match(pattern_name="aws_key")
    m2 = _make_match(pattern_name="github_token", value="ghp_abc")
    notes_map = {"aws_key": ["rotate immediately"]}
    noted = annotate_result([m1, m2], notes_map)
    assert len(noted) == 2
    assert noted[0].notes == ["rotate immediately"]
    assert noted[1].notes == []


def test_annotate_result_empty_matches():
    noted = annotate_result([], {"aws_key": ["note"]})
    assert noted == []


def test_annotate_result_no_notes_map():
    m = _make_match()
    noted = annotate_result([m], {})
    assert noted[0].notes == []
