"""Tests for hexpose.match_disposition."""
import pytest
from datetime import datetime, timezone

from hexpose.scanner import Match
from hexpose.match_disposition import (
    Disposition,
    DispositionMatch,
    dispose_match,
    dispose_all,
)


def _make_match(pattern_name="aws_key", value="AKIA1234", severity="high", offset=0):
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
        context="",
    )


def test_dispose_match_returns_disposition_match():
    m = _make_match()
    dm = dispose_match(m, "accept")
    assert isinstance(dm, DispositionMatch)


def test_dispose_match_stores_disposition():
    dm = dispose_match(_make_match(), "reject")
    assert dm.disposition == Disposition.REJECT


def test_dispose_match_stores_analyst():
    dm = dispose_match(_make_match(), "accept", analyst="alice")
    assert dm.analyst == "alice"


def test_dispose_match_strips_analyst_whitespace():
    dm = dispose_match(_make_match(), "accept", analyst="  bob  ")
    assert dm.analyst == "bob"


def test_dispose_match_stores_note():
    dm = dispose_match(_make_match(), "escalate", note="needs review")
    assert dm.note == "needs review"


def test_dispose_match_sets_decided_at_automatically():
    dm = dispose_match(_make_match(), "accept")
    assert isinstance(dm.decided_at, datetime)


def test_dispose_match_accepts_custom_decided_at():
    ts = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    dm = dispose_match(_make_match(), "accept", decided_at=ts)
    assert dm.decided_at == ts


def test_dispose_match_invalid_disposition_raises():
    with pytest.raises(ValueError):
        dispose_match(_make_match(), "unknown_value")


def test_disposition_validate_case_insensitive():
    assert Disposition.validate("ACCEPT") == "accept"
    assert Disposition.validate("Reject") == "reject"


def test_as_dict_contains_expected_keys():
    dm = dispose_match(_make_match(), "escalate", analyst="carol", note="check this")
    d = dm.as_dict()
    for key in ("pattern_name", "offset", "value", "disposition", "analyst", "note", "decided_at"):
        assert key in d


def test_as_dict_disposition_value():
    dm = dispose_match(_make_match(), "reject")
    assert dm.as_dict()["disposition"] == "reject"


def test_str_contains_disposition_and_pattern():
    dm = dispose_match(_make_match(pattern_name="jwt"), "escalate", analyst="dave")
    s = str(dm)
    assert "ESCALATE" in s
    assert "jwt" in s


def test_dispose_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="github_token", value="ghp_abc")]
    results = dispose_all(matches, "accept", analyst="eve")
    assert len(results) == 2
    assert all(isinstance(r, DispositionMatch) for r in results)


def test_dispose_all_same_disposition():
    matches = [_make_match(), _make_match()]
    results = dispose_all(matches, "reject")
    assert all(r.disposition == "reject" for r in results)


def test_dispose_all_empty_list():
    assert dispose_all([], "accept") == []
