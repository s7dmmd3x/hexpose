"""Tests for hexpose.context module."""

from __future__ import annotations

import pytest

from hexpose.context import MatchContext, extract_context


SAMPLE = b"line one\nline two\nSECRET=abc123\nline four\nline five\n"


# ---------------------------------------------------------------------------
# MatchContext.as_text
# ---------------------------------------------------------------------------

def test_as_text_marks_match_line():
    ctx = MatchContext(
        before_lines=["before"],
        match_line="SECRET=abc123",
        after_lines=["after"],
        line_number=3,
    )
    rendered = ctx.as_text(mark=True)
    assert "> SECRET=abc123" in rendered
    assert "  before" in rendered
    assert "  after" in rendered


def test_as_text_no_mark():
    ctx = MatchContext(match_line="SECRET=abc123")
    rendered = ctx.as_text(mark=False)
    assert rendered.startswith("  ")


# ---------------------------------------------------------------------------
# extract_context
# ---------------------------------------------------------------------------

def test_extract_context_returns_match_context():
    offset = SAMPLE.index(b"SECRET")
    ctx = extract_context(SAMPLE, offset, len(b"SECRET=abc123"))
    assert isinstance(ctx, MatchContext)


def test_extract_context_correct_match_line():
    offset = SAMPLE.index(b"SECRET")
    ctx = extract_context(SAMPLE, offset, len(b"SECRET=abc123"))
    assert "SECRET" in ctx.match_line


def test_extract_context_line_number():
    offset = SAMPLE.index(b"SECRET")
    ctx = extract_context(SAMPLE, offset, len(b"SECRET=abc123"))
    assert ctx.line_number == 3


def test_extract_context_before_lines():
    offset = SAMPLE.index(b"SECRET")
    ctx = extract_context(SAMPLE, offset, len(b"SECRET=abc123"), context_lines=2)
    assert "line one" in ctx.before_lines
    assert "line two" in ctx.before_lines


def test_extract_context_after_lines():
    offset = SAMPLE.index(b"SECRET")
    ctx = extract_context(SAMPLE, offset, len(b"SECRET=abc123"), context_lines=2)
    assert "line four" in ctx.after_lines


def test_extract_context_clamps_to_start():
    # offset at very first byte — no before lines
    ctx = extract_context(SAMPLE, 0, 4, context_lines=3)
    assert ctx.before_lines == []


def test_extract_context_clamps_to_end():
    last_line = b"line five\n"
    offset = len(SAMPLE) - len(last_line)
    ctx = extract_context(SAMPLE, offset, 4, context_lines=3)
    assert ctx.after_lines == []


def test_extract_context_empty_data():
    ctx = extract_context(b"", 0, 0)
    assert isinstance(ctx, MatchContext)


def test_extract_context_single_line():
    data = b"ONLY_LINE"
    ctx = extract_context(data, 0, len(data))
    assert ctx.match_line == "ONLY_LINE"
    assert ctx.before_lines == []
    assert ctx.after_lines == []


def test_extract_context_zero_context_lines():
    offset = SAMPLE.index(b"SECRET")
    ctx = extract_context(SAMPLE, offset, 6, context_lines=0)
    assert ctx.before_lines == []
    assert ctx.after_lines == []
