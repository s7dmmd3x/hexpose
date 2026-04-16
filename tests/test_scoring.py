"""Tests for hexpose.scoring."""
import pytest
from unittest.mock import MagicMock
from hexpose.scoring import score_match, score_result, ScoredMatch, _grade


def _make_match(severity="high", value="AKIAIOSFODNN7EXAMPLE"):
    m = MagicMock()
    m.severity = severity
    m.value = value
    return m


def _make_result(matches):
    r = MagicMock()
    r.matches = matches
    return r


def test_grade_critical():
    assert _grade(95) == "CRITICAL"


def test_grade_high():
    assert _grade(75) == "HIGH"


def test_grade_medium():
    assert _grade(55) == "MEDIUM"


def test_grade_low():
    assert _grade(35) == "LOW"


def test_grade_info():
    assert _grade(10) == "INFO"


def test_score_match_returns_scored_match():
    m = _make_match("high", "AKIAIOSFODNN7EXAMPLE")
    result = score_match(m)
    assert isinstance(result, ScoredMatch)


def test_score_match_base_score_high_severity():
    m = _make_match("high", "x")
    sm = score_match(m)
    assert sm.base_score == 60


def test_score_match_entropy_bonus_positive():
    m = _make_match("low", "aB3$kP9!mZqR2@nW")
    sm = score_match(m)
    assert sm.entropy_bonus > 0


def test_score_match_watchlist_bonus():
    m = _make_match("low", "x")
    sm_no = score_match(m, watchlisted=False)
    sm_yes = score_match(m, watchlisted=True)
    assert sm_yes.final_score == sm_no.final_score + 10.0


def test_score_match_final_capped_at_100():
    m = _make_match("critical", "aB3$kP9!mZqR2@nW5vXy")
    sm = score_match(m, watchlisted=True)
    assert sm.final_score <= 100.0


def test_score_match_empty_value():
    m = _make_match("medium", "")
    sm = score_match(m)
    assert sm.entropy_bonus == 0.0


def test_score_result_returns_list():
    matches = [_make_match("high"), _make_match("low")]
    result = _make_result(matches)
    scored = score_result(result)
    assert len(scored) == 2


def test_score_result_with_watchlist():
    wl = MagicMock()
    wl.contains.return_value = True
    matches = [_make_match("medium", "secret")]
    result = _make_result(matches)
    scored = score_result(result, watchlist=wl)
    assert scored[0].watchlist_bonus == 10.0


def test_score_result_empty():
    result = _make_result([])
    assert score_result(result) == []
