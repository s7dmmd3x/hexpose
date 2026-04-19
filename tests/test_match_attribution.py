"""Tests for hexpose.match_attribution and hexpose.attribution_report."""
import pytest
from unittest.mock import MagicMock

from hexpose.match_attribution import (
    AttributedMatch,
    attribute_match,
    attribute_all,
)
from hexpose.attribution_report import (
    format_attributed_match,
    format_attribution_report,
    attribution_summary,
)


def _make_match(pattern_name="aws_key", value="AKIA1234", severity="high", offset=0):
    m = MagicMock()
    m.pattern_name = pattern_name
    m.value = value
    m.severity = severity
    m.offset = offset
    return m


def _make_result(matches=None):
    r = MagicMock()
    r.matches = matches or []
    return r


def test_attribute_match_returns_attributed_match():
    m = _make_match()
    am = attribute_match(m)
    assert isinstance(am, AttributedMatch)


def test_attribute_match_stores_author():
    m = _make_match()
    am = attribute_match(m, author="alice")
    assert am.author == "alice"


def test_attribute_match_stores_team():
    m = _make_match()
    am = attribute_match(m, team="security")
    assert am.team == "security"


def test_attribute_match_stores_source_system():
    m = _make_match()
    am = attribute_match(m, source_system="ci-pipeline")
    assert am.source_system == "ci-pipeline"


def test_attribute_match_blank_author_defaults_to_unknown():
    m = _make_match()
    am = attribute_match(m, author="   ")
    assert am.author == "unknown"


def test_attribute_match_tags_normalised():
    m = _make_match()
    am = attribute_match(m, tags=["  FOO  ", "Bar", ""])
    assert am.tags == ["foo", "bar"]


def test_attribute_match_empty_tags_by_default():
    m = _make_match()
    am = attribute_match(m)
    assert am.tags == []


def test_as_dict_contains_expected_keys():
    m = _make_match()
    am = attribute_match(m, author="bob", team="ops", source_system="scanner")
    d = am.as_dict()
    for key in ("pattern_name", "value", "offset", "severity", "author", "team", "source_system", "tags"):
        assert key in d


def test_str_contains_pattern_name():
    m = _make_match(pattern_name="github_token")
    am = attribute_match(m)
    assert "github_token" in str(am)


def test_attribute_all_returns_list():
    r = _make_result([_make_match(), _make_match()])
    result = attribute_all(r, author="carol")
    assert len(result) == 2
    assert all(isinstance(x, AttributedMatch) for x in result)


def test_attribute_all_empty_result():
    r = _make_result([])
    assert attribute_all(r) == []


def test_format_attributed_match_contains_author():
    m = _make_match()
    am = attribute_match(m, author="dave")
    text = format_attributed_match(am)
    assert "dave" in text


def test_format_attribution_report_empty():
    assert format_attribution_report([]) == "No attributed matches."


def test_attribution_summary_counts():
    matches = [
        attribute_match(_make_match(), author="a", team="t1"),
        attribute_match(_make_match(), author="b", team="t2"),
    ]
    summary = attribution_summary(matches)
    assert "2 match" in summary
    assert "2 author" in summary


def test_attribution_summary_empty():
    assert "0 matches" in attribution_summary([])
