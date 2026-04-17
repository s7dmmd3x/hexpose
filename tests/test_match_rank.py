"""Tests for hexpose.match_rank and hexpose.rank_report."""
import pytest
from unittest.mock import MagicMock

from hexpose.match_rank import RankedMatch, rank_matches, top_n, _compute_rank
from hexpose.rank_report import format_ranked_match, format_rank_report, rank_summary


def _make_match(pattern_name="aws_key", value="AKIAIOSFODNN7EXAMPLE", severity="high"):
    m = MagicMock()
    m.pattern_name = pattern_name
    m.value = value
    m.severity = severity
    return m


def test_compute_rank_returns_ranked_match():
    m = _make_match()
    rm = _compute_rank(m)
    assert isinstance(rm, RankedMatch)
    assert rm.match is m


def test_rank_score_positive():
    rm = _compute_rank(_make_match(value="AKIAIOSFODNN7EXAMPLE", severity="critical"))
    assert rm.rank_score > 0


def test_severity_weight_critical_greater_than_low():
    rm_crit = _compute_rank(_make_match(severity="critical"))
    rm_low = _compute_rank(_make_match(severity="low"))
    assert rm_crit.rank_score > rm_low.rank_score


def test_rank_matches_sorted_descending():
    matches = [
        _make_match(severity="low", value="abc"),
        _make_match(severity="critical", value="AKIAIOSFODNN7EXAMPLE"),
        _make_match(severity="medium", value="secret123"),
    ]
    ranked = rank_matches(matches)
    scores = [r.rank_score for r in ranked]
    assert scores == sorted(scores, reverse=True)


def test_rank_matches_empty():
    assert rank_matches([]) == []


def test_top_n_limits_results():
    matches = [_make_match(value=f"val{i}", severity="medium") for i in range(20)]
    result = top_n(matches, n=5)
    assert len(result) == 5


def test_top_n_fewer_than_n():
    matches = [_make_match()]
    result = top_n(matches, n=10)
    assert len(result) == 1


def test_as_dict_contains_keys():
    rm = _compute_rank(_make_match())
    d = rm.as_dict()
    for key in ("pattern_name", "value", "entropy_score", "severity_weight", "rank_score"):
        assert key in d


def test_format_ranked_match_contains_name():
    rm = _compute_rank(_make_match(pattern_name="github_token"))
    out = format_ranked_match(rm, 0)
    assert "github_token" in out


def test_format_rank_report_empty():
    assert "No matches" in format_rank_report([])


def test_format_rank_report_lists_all():
    matches = [_make_match(pattern_name=f"pat{i}") for i in range(3)]
    ranked = rank_matches(matches)
    out = format_rank_report(ranked)
    for rm in ranked:
        assert rm.match.pattern_name in out


def test_rank_summary_empty():
    assert "0" in rank_summary([])


def test_rank_summary_shows_top():
    ranked = rank_matches([_make_match(pattern_name="top_pat", severity="critical")])
    summary = rank_summary(ranked)
    assert "top_pat" in summary
