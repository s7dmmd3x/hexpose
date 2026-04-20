"""Tests for match_sensitivity and sensitivity_report."""
import pytest
from hexpose.scanner import Match
from hexpose.match_sensitivity import (
    SensitivityMatch,
    classify_sensitivity,
    classify_sensitivity_all,
    _LEVELS,
)
from hexpose.sensitivity_report import (
    format_sensitivity_match,
    format_sensitivity_report,
    sensitivity_summary,
)


def _make_match(pattern_name: str = "aws_access_key", value: str = "AKIA1234") -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=0, severity="high")


def test_classify_sensitivity_returns_sensitivity_match():
    m = _make_match()
    result = classify_sensitivity(m)
    assert isinstance(result, SensitivityMatch)


def test_classify_aws_key_gives_restricted():
    m = _make_match(pattern_name="aws_access_key")
    result = classify_sensitivity(m)
    assert result.sensitivity == "restricted"


def test_classify_aws_secret_gives_confidential():
    m = _make_match(pattern_name="aws_secret_key")
    result = classify_sensitivity(m)
    assert result.sensitivity == "confidential"


def test_classify_unknown_pattern_defaults_to_internal():
    m = _make_match(pattern_name="unknown_pattern_xyz")
    result = classify_sensitivity(m)
    assert result.sensitivity == "internal"


def test_classify_override_respected():
    m = _make_match()
    result = classify_sensitivity(m, override="public")
    assert result.sensitivity == "public"


def test_classify_invalid_override_defaults_to_internal():
    m = _make_match()
    result = classify_sensitivity(m, override="top_secret")
    assert result.sensitivity == "internal"


def test_level_is_int_index():
    m = _make_match(pattern_name="aws_secret_key")
    result = classify_sensitivity(m)
    assert result.level == _LEVELS.index("confidential")


def test_notes_stored():
    m = _make_match()
    result = classify_sensitivity(m, notes="manual review")
    assert result.notes == "manual review"


def test_as_dict_contains_keys():
    m = _make_match()
    d = classify_sensitivity(m).as_dict()
    for key in ("pattern_name", "offset", "sensitivity", "level", "notes"):
        assert key in d


def test_str_contains_sensitivity_and_pattern():
    m = _make_match()
    sm = classify_sensitivity(m)
    s = str(sm)
    assert sm.sensitivity.upper() in s
    assert m.pattern_name in s


def test_classify_sensitivity_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="jwt")]
    results = classify_sensitivity_all(matches)
    assert len(results) == 2
    assert all(isinstance(r, SensitivityMatch) for r in results)


def test_format_sensitivity_match_contains_pattern_name():
    sm = classify_sensitivity(_make_match())
    text = format_sensitivity_match(sm, colour=False)
    assert sm.match.pattern_name in text


def test_format_sensitivity_match_contains_sensitivity():
    sm = classify_sensitivity(_make_match())
    text = format_sensitivity_match(sm, colour=False)
    assert sm.sensitivity.upper() in text


def test_format_sensitivity_report_empty():
    text = format_sensitivity_report([], colour=False)
    assert "No" in text


def test_format_sensitivity_report_includes_matches():
    items = classify_sensitivity_all([_make_match(), _make_match(pattern_name="jwt")])
    text = format_sensitivity_report(items, colour=False)
    assert "aws_access_key" in text


def test_sensitivity_summary_counts():
    items = classify_sensitivity_all([
        _make_match(pattern_name="aws_secret_key"),
        _make_match(pattern_name="aws_secret_key"),
        _make_match(pattern_name="jwt"),
    ])
    summary = sensitivity_summary(items)
    assert summary["confidential"] == 2
    assert summary["internal"] == 1
