"""Tests for hexpose.triage module."""

import pytest
from unittest.mock import MagicMock

from hexpose.triage import (
    triage_match,
    triage_result,
    TriagedMatch,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_MEDIUM,
    RISK_LOW,
)
from hexpose.scanner import Match, ScanResult


def _make_match(value="secret", severity="medium", offset=0, pattern_name="test"):
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
        context="",
    )


def _make_result(matches=None):
    return ScanResult(source="test.bin", matches=matches or [])


def test_triage_match_returns_triaged_match():
    m = _make_match(severity="high")
    result = triage_match(m)
    assert isinstance(result, TriagedMatch)
    assert result.match is m


def test_triage_low_severity_gives_low_risk():
    m = _make_match(value="abc", severity="low")
    t = triage_match(m)
    assert t.risk in (RISK_LOW, RISK_MEDIUM)  # may upgrade due to entropy


def test_triage_critical_severity_gives_critical_risk():
    m = _make_match(value="abc", severity="critical")
    t = triage_match(m)
    assert t.risk == RISK_CRITICAL


def test_triage_high_entropy_upgrades_medium_to_high():
    # 32-char random-looking string has high entropy
    high_ent_value = "aB3$xQ9!mZ2#kL5@nP7^wR1&yT4*uI6("
    m = _make_match(value=high_ent_value, severity="medium")
    t = triage_match(m)
    assert t.risk == RISK_HIGH
    assert any("entropy" in r for r in t.reasons)


def test_triage_watchlist_hit_escalates_to_critical():
    wl = MagicMock()
    wl.contains.return_value = True
    m = _make_match(value="mysecret", severity="low")
    t = triage_match(m, watchlist=wl)
    assert t.risk == RISK_CRITICAL
    assert any("watchlist" in r for r in t.reasons)


def test_triage_watchlist_miss_no_escalation():
    wl = MagicMock()
    wl.contains.return_value = False
    m = _make_match(value="abc", severity="low")
    t = triage_match(m, watchlist=wl)
    assert t.risk != RISK_CRITICAL


def test_triage_result_returns_list_per_match():
    matches = [_make_match(severity="high"), _make_match(severity="low")]
    result = _make_result(matches=matches)
    triaged = triage_result(result)
    assert len(triaged) == 2
    assert all(isinstance(t, TriagedMatch) for t in triaged)


def test_triage_result_empty_matches():
    result = _make_result(matches=[])
    assert triage_result(result) == []


def test_triage_reasons_populated():
    m = _make_match(severity="high")
    t = triage_match(m)
    assert len(t.reasons) > 0
