"""Tests for hexpose.annotation."""
from hexpose.scanner import Match
from hexpose.annotation import (
    AnnotatedMatch,
    annotate_match,
    annotate_matches,
    merge_annotations,
)


def _make_match(
    pattern_name: str = "aws_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    offset: int = 0,
    severity: str = "high",
) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


def test_annotate_match_returns_annotated_match():
    m = _make_match()
    am = annotate_match(m, source="elf")
    assert isinstance(am, AnnotatedMatch)
    assert am.match is m


def test_annotate_match_seeds_kwargs():
    m = _make_match()
    am = annotate_match(m, source="elf", reviewed=False)
    assert am.get("source") == "elf"
    assert am.get("reviewed") is False


def test_annotate_default_missing_key_returns_default():
    am = annotate_match(_make_match())
    assert am.get("nonexistent", "fallback") == "fallback"


def test_annotate_overwrite():
    am = annotate_match(_make_match(), label="old")
    am.annotate("label", "new")
    assert am.get("label") == "new"


def test_as_dict_contains_expected_keys():
    m = _make_match()
    am = annotate_match(m, note="test")
    d = am.as_dict()
    assert "pattern_name" in d
    assert "value" in d
    assert "annotations" in d
    assert d["annotations"]["note"] == "test"


def test_annotate_matches_bulk():
    matches = [_make_match(offset=i) for i in range(4)]
    annotated = annotate_matches(matches, source="dump")
    assert len(annotated) == 4
    assert all(a.get("source") == "dump" for a in annotated)


def test_annotate_matches_empty():
    assert annotate_matches([]) == []


def test_merge_annotations_does_not_mutate_base():
    am = annotate_match(_make_match(), x=1)
    merged = merge_annotations(am, {"y": 2})
    assert merged.get("y") == 2
    assert am.get("y", None) is None


def test_merge_annotations_overwrites_existing():
    am = annotate_match(_make_match(), x=1)
    merged = merge_annotations(am, {"x": 99})
    assert merged.get("x") == 99


def test_merge_preserves_original_annotations():
    am = annotate_match(_make_match(), keep="yes")
    merged = merge_annotations(am, {"extra": "val"})
    assert merged.get("keep") == "yes"
