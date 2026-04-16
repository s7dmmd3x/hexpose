"""Tests for hexpose.watchlist and hexpose.watchlist_annotator."""

from __future__ import annotations

import json
import pathlib

import pytest

from hexpose.watchlist import Watchlist
from hexpose.watchlist_annotator import (
    WATCHLIST_KEY,
    annotate_match,
    annotate_result,
    watchlisted_matches,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_match(value: str = "AKIAIOSFODNN7EXAMPLE"):
    from hexpose.scanner import Match
    return Match(
        pattern_name="aws_access_key",
        value=value,
        offset=0,
        line=1,
        severity="high",
        metadata={},
    )


def _make_result(matches):
    from hexpose.scanner import ScanResult
    return ScanResult(source="test", matches=matches)


# ---------------------------------------------------------------------------
# Watchlist unit tests
# ---------------------------------------------------------------------------

def test_watchlist_empty_by_default():
    wl = Watchlist()
    assert len(wl) == 0


def test_watchlist_add_and_contains():
    wl = Watchlist()
    wl.add("secret123")
    assert "secret123" in wl


def test_watchlist_remove():
    wl = Watchlist(["a", "b"])
    wl.remove("a")
    assert "a" not in wl
    assert "b" in wl


def test_watchlist_remove_missing_is_silent():
    wl = Watchlist()
    wl.remove("nonexistent")  # should not raise


def test_watchlist_load_missing_file(tmp_path):
    wl = Watchlist.load(tmp_path / "missing.json")
    assert len(wl) == 0


def test_watchlist_save_and_load(tmp_path):
    p = tmp_path / "wl.json"
    wl = Watchlist(["val1", "val2"])
    wl.save(p)
    loaded = Watchlist.load(p)
    assert "val1" in loaded
    assert "val2" in loaded


def test_watchlist_load_invalid_json_type(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"key": "value"}))
    with pytest.raises(ValueError, match="JSON array"):
        Watchlist.load(p)


def test_is_watchlisted_true():
    wl = Watchlist(["AKIAIOSFODNN7EXAMPLE"])
    m = _make_match("AKIAIOSFODNN7EXAMPLE")
    assert wl.is_watchlisted(m) is True


def test_is_watchlisted_false():
    wl = Watchlist(["other_value"])
    m = _make_match("AKIAIOSFODNN7EXAMPLE")
    assert wl.is_watchlisted(m) is False


def test_filter_watchlisted():
    wl = Watchlist(["known_bad"])
    matches = [_make_match("known_bad"), _make_match("clean_value")]
    result = wl.filter_watchlisted(matches)
    assert len(result) == 1
    assert result[0].value == "known_bad"


# ---------------------------------------------------------------------------
# Annotator tests
# ---------------------------------------------------------------------------

def test_annotate_match_sets_flag_true():
    wl = Watchlist(["AKIAIOSFODNN7EXAMPLE"])
    m = _make_match("AKIAIOSFODNN7EXAMPLE")
    annotate_match(m, wl)
    assert m.metadata[WATCHLIST_KEY] is True


def test_annotate_match_sets_flag_false():
    wl = Watchlist()
    m = _make_match("AKIAIOSFODNN7EXAMPLE")
    annotate_match(m, wl)
    assert m.metadata[WATCHLIST_KEY] is False


def test_annotate_result_annotates_all_matches():
    wl = Watchlist(["known_bad"])
    matches = [_make_match("known_bad"), _make_match("clean")]
    result = _make_result(matches)
    annotate_result(result, wl)
    flags = [m.metadata[WATCHLIST_KEY] for m in result.matches]
    assert flags == [True, False]


def test_watchlisted_matches_returns_subset():
    wl = Watchlist(["known_bad"])
    matches = [_make_match("known_bad"), _make_match("clean")]
    result = _make_result(matches)
    found = watchlisted_matches(result, wl)
    assert len(found) == 1
    assert found[0].value == "known_bad"
