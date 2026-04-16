"""Tests for hexpose.tag and hexpose.tag_report."""
import pytest

from hexpose.scanner import Match
from hexpose.tag import (
    TaggedMatch,
    all_tags,
    filter_by_tag,
    tag_match,
)
from hexpose.tag_report import format_tag_report, format_tagged_match, tag_summary


def _make_match(name: str = "aws_key", value: str = "AKIA1234", offset: int = 0) -> Match:
    return Match(pattern_name=name, value=value, offset=offset, severity="high")


def test_tag_match_returns_tagged_match():
    m = _make_match()
    tm = tag_match(m, "cloud", "aws")
    assert isinstance(tm, TaggedMatch)
    assert tm.has("cloud")
    assert tm.has("aws")


def test_tag_match_normalises_case():
    tm = tag_match(_make_match(), "AWS", " Cloud ")
    assert tm.has("aws")
    assert tm.has("cloud")


def test_tag_match_empty_tag_ignored():
    tm = tag_match(_make_match(), "", "  ")
    assert tm.tags == set()


def test_has_missing_tag_returns_false():
    tm = tag_match(_make_match(), "aws")
    assert not tm.has("gcp")


def test_as_dict_contains_tags():
    tm = tag_match(_make_match(), "a", "b")
    d = tm.as_dict()
    assert set(d["tags"]) == {"a", "b"}
    assert d["pattern_name"] == "aws_key"


def test_filter_by_tag_returns_matching():
    matches = [
        tag_match(_make_match(), "aws"),
        tag_match(_make_match(name="gh_token"), "github"),
        tag_match(_make_match(name="slack"), "aws", "slack"),
    ]
    result = filter_by_tag(matches, "aws")
    assert len(result) == 2
    assert all(t.has("aws") for t in result)


def test_filter_by_tag_empty_list():
    assert filter_by_tag([], "aws") == []


def test_all_tags_collects_unique():
    matches = [
        tag_match(_make_match(), "aws", "cloud"),
        tag_match(_make_match(), "cloud", "prod"),
    ]
    tags = all_tags(matches)
    assert tags == {"aws", "cloud", "prod"}


def test_all_tags_empty():
    assert all_tags([]) == set()


def test_format_tagged_match_contains_pattern_name():
    tm = tag_match(_make_match(), "aws")
    text = format_tagged_match(tm, color=False)
    assert "aws_key" in text
    assert "aws" in text


def test_format_tag_report_empty():
    assert format_tag_report([], color=False) == "No tagged matches."


def test_format_tag_report_includes_unique_tags():
    matches = [tag_match(_make_match(), "aws"), tag_match(_make_match(), "gcp")]
    report = format_tag_report(matches, color=False)
    assert "aws" in report
    assert "gcp" in report
    assert "Unique tags" in report


def test_tag_summary_counts():
    matches = [
        tag_match(_make_match(), "aws"),
        tag_match(_make_match(), "aws", "prod"),
    ]
    s = tag_summary(matches)
    assert s["total"] == 2
    assert s["counts"]["aws"] == 2
    assert s["counts"]["prod"] == 1
    assert s["unique_tags"] == 2
