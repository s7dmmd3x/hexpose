"""Tests for hexpose.redactor."""

import pytest

from hexpose.redactor import (
    redact_full,
    redact_partial,
    redact_value,
    redact_line,
    apply_redaction,
)


def test_redact_full_returns_placeholder():
    assert redact_full("supersecret") == "[REDACTED]"


def test_redact_full_empty_string():
    assert redact_full("") == "[REDACTED]"


def test_redact_partial_short_value():
    # shorter than 2*_PARTIAL_SHOW → full redaction
    assert redact_partial("abc") == "[REDACTED]"


def test_redact_partial_long_value():
    result = redact_partial("AKIAIOSFODNN7EXAMPLE")
    assert result.startswith("AKIA")
    assert result.endswith("MPLE")
    assert "*" in result
    assert "IOSFODNN7EXA" not in result


def test_redact_value_mode_full():
    assert redact_value("topsecret", mode="full") == "[REDACTED]"


def test_redact_value_mode_partial_default():
    result = redact_value("AKIAIOSFODNN7EXAMPLE")
    assert result != "AKIAIOSFODNN7EXAMPLE"
    assert "AKIA" in result


def test_redact_value_unknown_mode_falls_back_to_partial():
    result = redact_value("AKIAIOSFODNN7EXAMPLE", mode="unknown")
    assert result.startswith("AKIA")


def test_redact_line_replaces_value():
    line = "export AWS_SECRET=AKIAIOSFODNN7EXAMPLE"
    result = redact_line(line, "AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "export AWS_SECRET=" in result


def test_redact_line_empty_value_unchanged():
    line = "nothing to redact"
    assert redact_line(line, "") == line


def test_apply_redaction_multiple_values():
    text = "key1=SECRET1 key2=ANOTHERSECRETVALUE"
    result = apply_redaction(text, ["SECRET1", "ANOTHERSECRETVALUE"])
    assert "SECRET1" not in result
    assert "ANOTHERSECRETVALUE" not in result


def test_apply_redaction_empty_values_list():
    text = "unchanged text"
    assert apply_redaction(text, []) == text


def test_apply_redaction_full_mode():
    text = "token=AKIAIOSFODNN7EXAMPLE"
    result = apply_redaction(text, ["AKIAIOSFODNN7EXAMPLE"], mode="full")
    assert "[REDACTED]" in result
    assert "AKIAIOSFODNN7EXAMPLE" not in result
