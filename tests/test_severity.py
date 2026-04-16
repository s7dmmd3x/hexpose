"""Tests for hexpose.severity."""

import pytest

from hexpose.severity import (
    ALL_SEVERITIES,
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    Severity,
    parse_severity,
    severity_at_least,
)


# ---------------------------------------------------------------------------
# Severity.from_string
# ---------------------------------------------------------------------------


def test_from_string_lowercase():
    assert Severity.from_string("low") is LOW


def test_from_string_uppercase():
    assert Severity.from_string("CRITICAL") is CRITICAL


def test_from_string_mixed_case():
    assert Severity.from_string("Medium") is MEDIUM


def test_from_string_with_whitespace():
    assert Severity.from_string("  high  ") is HIGH


def test_from_string_invalid_raises():
    with pytest.raises(ValueError, match="Unknown severity"):
        Severity.from_string("extreme")


def test_from_string_invalid_includes_valid_values():
    with pytest.raises(ValueError, match="low"):
        Severity.from_string("bad")


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


def test_ordering_low_less_than_critical():
    assert LOW < CRITICAL


def test_ordering_high_greater_than_medium():
    assert HIGH > MEDIUM


def test_ordering_equal():
    assert Severity.from_string("high") == HIGH


# ---------------------------------------------------------------------------
# label / str
# ---------------------------------------------------------------------------


def test_label_returns_lowercase():
    assert HIGH.label() == "high"


def test_all_labels_lowercase():
    for s in Severity:
        assert s.label() == s.label().lower()


# ---------------------------------------------------------------------------
# parse_severity helper
# ---------------------------------------------------------------------------


def test_parse_severity_delegates():
    assert parse_severity("medium") is MEDIUM


# ---------------------------------------------------------------------------
# severity_at_least
# ---------------------------------------------------------------------------


def test_severity_at_least_no_minimum():
    assert severity_at_least(LOW, None) is True


def test_severity_at_least_equal():
    assert severity_at_least(MEDIUM, MEDIUM) is True


def test_severity_at_least_above():
    assert severity_at_least(HIGH, MEDIUM) is True


def test_severity_at_least_below():
    assert severity_at_least(LOW, HIGH) is False


# ---------------------------------------------------------------------------
# ALL_SEVERITIES
# ---------------------------------------------------------------------------


def test_all_severities_contains_four_levels():
    assert len(ALL_SEVERITIES) == 4


def test_all_severities_ordered():
    assert ALL_SEVERITIES == sorted(ALL_SEVERITIES)
