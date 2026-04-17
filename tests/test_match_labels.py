"""Tests for hexpose.match_labels."""
import pytest
from hexpose.scanner import Match
from hexpose.match_labels import (
    LabeledMatch,
    label_match,
    matches_with_label,
    label_summary,
)


def _make_match(name="aws_key", value="AKIA1234567890ABCDEF") -> Match:
    return Match(pattern_name=name, value=value, offset=0, severity="high")


def test_label_match_returns_labeled_match():
    m = _make_match()
    lm = label_match(m)
    assert isinstance(lm, LabeledMatch)
    assert lm.match is m


def test_label_match_applies_labels():
    m = _make_match()
    lm = label_match(m, "cloud", "critical-asset")
    assert lm.has("cloud")
    assert lm.has("critical-asset")


def test_add_strips_whitespace():
    lm = LabeledMatch(match=_make_match())
    lm.add("  pii  ")
    assert lm.has("pii")


def test_add_ignores_empty_string():
    lm = LabeledMatch(match=_make_match())
    lm.add("")
    assert lm.labels == []


def test_add_no_duplicates():
    lm = LabeledMatch(match=_make_match())
    lm.add("cloud")
    lm.add("cloud")
    assert lm.labels.count("cloud") == 1


def test_has_missing_label_returns_false():
    lm = LabeledMatch(match=_make_match())
    assert not lm.has("unknown")


def test_as_dict_contains_keys():
    lm = label_match(_make_match(), "pii")
    d = lm.as_dict()
    assert "pattern_name" in d
    assert "value" in d
    assert "labels" in d
    assert "pii" in d["labels"]


def test_matches_with_label_filters_correctly():
    m1 = label_match(_make_match("aws_key"), "cloud")
    m2 = label_match(_make_match("github_token"), "vcs")
    m3 = label_match(_make_match("stripe_key"), "cloud", "payments")
    result = matches_with_label([m1, m2, m3], "cloud")
    assert len(result) == 2
    assert m2 not in result


def test_matches_with_label_empty_list():
    assert matches_with_label([], "cloud") == []


def test_label_summary_counts():
    m1 = label_match(_make_match(), "cloud", "pii")
    m2 = label_match(_make_match(), "cloud")
    summary = label_summary([m1, m2])
    assert summary["cloud"] == 2
    assert summary["pii"] == 1


def test_label_summary_empty():
    assert label_summary([]) == {}
