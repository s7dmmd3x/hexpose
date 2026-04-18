"""Tests for hexpose.match_highlight."""
import pytest
from unittest.mock import MagicMock

from hexpose.match_highlight import (
    highlight_match,
    highlight_all,
    HighlightedMatch,
    _colorize,
)


def _make_match(value: str, offset: int, pattern_name: str = "test_pattern", severity: str = "high"):
    m = MagicMock()
    m.value = value
    m.offset = offset
    m.pattern_name = pattern_name
    m.severity = severity
    return m


def test_colorize_contains_value():
    result = _colorize("SECRET")
    assert "SECRET" in result


def test_colorize_adds_ansi_codes():
    result = _colorize("X")
    assert "\033[" in result


def test_highlight_match_returns_highlighted_match():
    source = b"line one\nAKIA1234567890ABCDEF is here\n"
    value = "AKIA1234567890ABCDEF"
    offset = source.index(value.encode())
    m = _make_match(value, offset)
    hm = highlight_match(m, source)
    assert isinstance(hm, HighlightedMatch)


def test_highlight_match_correct_line():
    source = b"first line\nmy_secret=hunter2\n"
    value = "hunter2"
    offset = source.index(b"hunter2")
    m = _make_match(value, offset)
    hm = highlight_match(m, source)
    assert "hunter2" in hm.line
    assert "first line" not in hm.line


def test_highlight_match_start_in_line():
    source = b"prefix_hunter2_suffix\n"
    value = "hunter2"
    offset = source.index(b"hunter2")
    m = _make_match(value, offset)
    hm = highlight_match(m, source)
    assert hm.start_in_line == len("prefix_")


def test_highlight_match_end_in_line():
    source = b"prefix_hunter2_suffix\n"
    value = "hunter2"
    offset = source.index(b"hunter2")
    m = _make_match(value, offset)
    hm = highlight_match(m, source)
    assert hm.end_in_line == hm.start_in_line + len(value)


def test_highlighted_line_contains_ansi():
    source = b"token=abc123\n"
    value = "abc123"
    offset = source.index(b"abc123")
    m = _make_match(value, offset)
    hm = highlight_match(m, source)
    assert "\033[" in hm.highlighted_line


def test_as_dict_has_expected_keys():
    source = b"token=abc123\n"
    value = "abc123"
    offset = source.index(b"abc123")
    m = _make_match(value, offset)
    hm = highlight_match(m, source)
    d = hm.as_dict()
    for key in ("pattern_name", "value", "line", "highlighted_line", "start_in_line", "end_in_line"):
        assert key in d


def test_highlight_all_returns_list():
    source = b"key=abc\nsecret=xyz\n"
    matches = [
        _make_match("abc", source.index(b"abc")),
        _make_match("xyz", source.index(b"xyz")),
    ]
    results = highlight_all(matches, source)
    assert len(results) == 2
    assert all(isinstance(r, HighlightedMatch) for r in results)


def test_highlight_match_fallback_on_missing_offset():
    source = b"nothing relevant\n"
    m = _make_match("SECRET", 9999)
    hm = highlight_match(m, source)
    assert hm.value == "SECRET"
    assert "SECRET" in hm.highlighted_line
