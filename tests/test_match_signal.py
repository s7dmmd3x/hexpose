"""Tests for hexpose.match_signal and hexpose.signal_report."""
from __future__ import annotations

import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_signal import (
    SignalMatch,
    _label,
    _entropy_factor,
    signal_match,
    signal_all,
)
from hexpose.signal_report import (
    format_signal_match,
    format_signal_report,
    signal_summary,
)


def _make_match(
    pattern: str = "aws_access_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    severity: str = "high",
    offset: int = 0,
) -> Match:
    return Match(pattern_name=pattern, value=value, offset=offset, severity=severity)


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test", matches=matches or [])


# ── _label ──────────────────────────────────────────────────────────────────

def test_label_strong():
    assert _label(0.8) == "strong"

def test_label_moderate():
    assert _label(0.5) == "moderate"

def test_label_weak():
    assert _label(0.1) == "weak"

def test_label_boundary_strong():
    assert _label(0.65) == "strong"

def test_label_boundary_moderate():
    assert _label(0.35) == "moderate"


# ── _entropy_factor ──────────────────────────────────────────────────────────

def test_entropy_factor_empty_string():
    assert _entropy_factor("") == 0.0

def test_entropy_factor_capped_at_one():
    # Random-looking string should yield a factor ≤ 1.0
    factor = _entropy_factor("aB3$xQ9!zL2#mN7@")
    assert 0.0 <= factor <= 1.0

def test_entropy_factor_uniform_string_is_low():
    factor = _entropy_factor("aaaaaaaaaa")
    assert factor < 0.2


# ── signal_match ─────────────────────────────────────────────────────────────

def test_signal_match_returns_signal_match():
    m = _make_match()
    sm = signal_match(m)
    assert isinstance(sm, SignalMatch)

def test_signal_match_score_between_zero_and_one():
    sm = signal_match(_make_match())
    assert 0.0 <= sm.signal_score <= 1.0

def test_signal_match_critical_higher_than_low():
    sm_crit = signal_match(_make_match(severity="critical"))
    sm_low  = signal_match(_make_match(severity="low"))
    assert sm_crit.signal_score > sm_low.signal_score

def test_signal_match_label_is_string():
    sm = signal_match(_make_match())
    assert sm.signal_label in ("strong", "moderate", "weak")

def test_signal_match_as_dict_keys():
    sm = signal_match(_make_match())
    d = sm.as_dict()
    for key in ("pattern", "value", "offset", "severity",
                "entropy", "severity_weight", "signal_score", "signal_label"):
        assert key in d

def test_signal_match_str_contains_label():
    sm = signal_match(_make_match(severity="critical"))
    assert sm.signal_label.upper() in str(sm)


# ── signal_all ───────────────────────────────────────────────────────────────

def test_signal_all_empty_result():
    result = _make_result([])
    assert signal_all(result) == []

def test_signal_all_returns_one_per_match():
    matches = [_make_match(), _make_match(pattern="github_token", value="ghp_abc")]
    result = _make_result(matches)
    sigs = signal_all(result)
    assert len(sigs) == 2


# ── format helpers ────────────────────────────────────────────────────────────

def test_format_signal_match_contains_pattern_name():
    sm = signal_match(_make_match(pattern="my_pattern"))
    assert "my_pattern" in format_signal_match(sm, color=False)

def test_format_signal_match_contains_score():
    sm = signal_match(_make_match())
    text = format_signal_match(sm, color=False)
    assert "score=" in text

def test_format_signal_report_empty():
    assert format_signal_report([], color=False) == "No signals found."

def test_format_signal_report_sorted_descending():
    matches = [
        _make_match(severity="low",      value="aaa"),
        _make_match(severity="critical", value="AKIAIOSFODNN7EXAMPLE"),
    ]
    sigs = [signal_match(m) for m in matches]
    report = format_signal_report(sigs, color=False)
    idx_crit = report.index("critical")
    idx_low  = report.index("low")
    assert idx_crit < idx_low

def test_signal_summary_empty():
    assert signal_summary([]) == "Signals: 0"

def test_signal_summary_counts():
    matches = [
        _make_match(severity="critical"),
        _make_match(severity="low", value="aaa"),
    ]
    sigs = [signal_match(m) for m in matches]
    summary = signal_summary(sigs)
    assert "Signals: 2" in summary
