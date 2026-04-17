"""Tests for hexpose.remediation and hexpose.remediation_report."""
import pytest
from unittest.mock import MagicMock
from hexpose.remediation import (
    RemediationHint,
    get_hint,
    annotate_match,
    _HINTS,
    _DEFAULT_HINT,
)
from hexpose.remediation_report import (
    format_hint,
    format_remediation_report,
    remediation_summary,
)


def _make_match(pattern_name: str = "aws_access_key", value: str = "AKIAIOSFODNN7EXAMPLE"):
    m = MagicMock()
    m.pattern_name = pattern_name
    m.value = value
    return m


def _make_result(matches):
    r = MagicMock()
    r.matches = matches
    return r


# --- remediation.py ---

def test_get_hint_known_pattern():
    hint = get_hint("aws_access_key")
    assert isinstance(hint, RemediationHint)
    assert hint.pattern_name == "aws_access_key"


def test_get_hint_unknown_returns_default():
    hint = get_hint("totally_unknown_pattern_xyz")
    assert hint is _DEFAULT_HINT


def test_hint_as_dict_contains_keys():
    hint = get_hint("aws_access_key")
    d = hint.as_dict()
    assert "pattern_name" in d
    assert "summary" in d
    assert "steps" in d
    assert isinstance(d["steps"], list)
    assert len(d["steps"]) > 0


def test_hint_reference_optional():
    hint = get_hint("generic_secret")
    d = hint.as_dict()
    assert d["reference"] is None


def test_annotate_match_returns_dict():
    m = _make_match()
    result = annotate_match(m)
    assert "match" in result
    assert "remediation" in result


def test_annotate_match_remediation_has_steps():
    m = _make_match("github_token")
    result = annotate_match(m)
    assert len(result["remediation"]["steps"]) > 0


# --- remediation_report.py ---

def test_format_hint_contains_summary():
    hint = get_hint("aws_access_key")
    text = format_hint(hint, color=False)
    assert hint.summary in text


def test_format_hint_contains_steps():
    hint = get_hint("aws_access_key")
    text = format_hint(hint, color=False)
    for step in hint.steps:
        assert step in text


def test_format_hint_contains_reference():
    hint = get_hint("aws_access_key")
    text = format_hint(hint, color=False)
    assert hint.reference in text


def test_format_hint_no_reference_skipped():
    hint = get_hint("generic_secret")
    text = format_hint(hint, color=False)
    assert "Ref:" not in text


def test_format_remediation_report_empty():
    text = format_remediation_report([], color=False)
    assert "nothing to remediate" in text.lower()


def test_format_remediation_report_deduplicates():
    matches = [_make_match("aws_access_key"), _make_match("aws_access_key")]
    text = format_remediation_report(matches, color=False)
    # summary should appear only once
    hint = get_hint("aws_access_key")
    assert text.count(hint.summary) == 1


def test_format_remediation_report_multiple_patterns():
    matches = [_make_match("aws_access_key"), _make_match("github_token")]
    text = format_remediation_report(matches, color=False)
    assert "aws_access_key" in text
    assert "github_token" in text


def test_remediation_summary_delegates_to_result():
    matches = [_make_match("generic_secret")]
    result = _make_result(matches)
    text = remediation_summary(result, color=False)
    assert "generic_secret" in text
