"""Tests for hexpose.match_validator."""
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_validator import (
    ValidatedMatch,
    validate_match,
    validate_result,
)


def _make_match(
    value: str = "AKIAIOSFODNN7EXAMPLE",
    pattern_name: str = "aws_access_key",
    severity: str = "high",
    offset: int = 0,
) -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
    )


def _make_result(matches=None) -> ScanResult:
    return ScanResult(
        source="test.bin",
        matches=matches or [],
    )


# ---------------------------------------------------------------------------
# ValidatedMatch
# ---------------------------------------------------------------------------

def test_validated_match_is_valid_when_no_errors():
    vm = ValidatedMatch(match=_make_match(), errors=[])
    assert vm.is_valid is True


def test_validated_match_is_invalid_when_errors_present():
    vm = ValidatedMatch(match=_make_match(), errors=["something wrong"])
    assert vm.is_valid is False


def test_as_dict_contains_required_keys():
    vm = ValidatedMatch(match=_make_match(), errors=[])
    d = vm.as_dict()
    for key in ("pattern_name", "value", "offset", "severity", "is_valid", "errors"):
        assert key in d


def test_as_dict_errors_list_is_copy():
    vm = ValidatedMatch(match=_make_match(), errors=["e1"])
    d = vm.as_dict()
    d["errors"].append("e2")
    assert len(vm.errors) == 1


# ---------------------------------------------------------------------------
# validate_match
# ---------------------------------------------------------------------------

def test_validate_match_returns_validated_match():
    result = validate_match(_make_match())
    assert isinstance(result, ValidatedMatch)


def test_validate_match_valid_by_default():
    result = validate_match(_make_match())
    assert result.is_valid


def test_validate_match_empty_value_is_invalid():
    m = _make_match(value="   ")
    result = validate_match(m)
    assert not result.is_valid
    assert any("empty" in e for e in result.errors)


def test_validate_match_below_min_length_is_invalid():
    m = _make_match(value="abc")
    result = validate_match(m, min_length=10)
    assert not result.is_valid
    assert any("minimum" in e for e in result.errors)


def test_validate_match_above_max_length_is_invalid():
    m = _make_match(value="x" * 100)
    result = validate_match(m, max_length=10)
    assert not result.is_valid
    assert any("exceeds" in e for e in result.errors)


def test_validate_match_disallowed_severity_is_invalid():
    m = _make_match(severity="low")
    result = validate_match(m, allowed_severities=["high", "critical"])
    assert not result.is_valid
    assert any("severity" in e for e in result.errors)


def test_validate_match_allowed_severity_is_valid():
    m = _make_match(severity="high")
    result = validate_match(m, allowed_severities=["high", "critical"])
    assert result.is_valid


def test_validate_match_multiple_errors_accumulated():
    m = _make_match(value="x", severity="low")
    result = validate_match(m, min_length=5, allowed_severities=["high"])
    assert len(result.errors) >= 2


# ---------------------------------------------------------------------------
# validate_result
# ---------------------------------------------------------------------------

def test_validate_result_returns_list():
    r = _make_result([_make_match(), _make_match()])
    results = validate_result(r)
    assert isinstance(results, list)
    assert len(results) == 2


def test_validate_result_empty_matches():
    r = _make_result([])
    results = validate_result(r)
    assert results == []


def test_validate_result_propagates_kwargs():
    r = _make_result([_make_match(value="short")])
    results = validate_result(r, min_length=20)
    assert not results[0].is_valid
