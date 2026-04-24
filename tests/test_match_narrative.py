"""Tests for hexpose.match_narrative."""
from __future__ import annotations

import pytest

from hexpose.scanner import Match
from hexpose.match_narrative import (
    NarrativeMatch,
    attach_narrative,
    attach_narrative_all,
    _lookup_narrative,
    _build_recommendations,
    _DEFAULT_NARRATIVE,
)


def _make_match(
    pattern_name: str = "generic_secret",
    value: str = "s3cr3t",
    severity: str = "medium",
    offset: int = 0,
) -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
    )


# --- _lookup_narrative ---

def test_lookup_narrative_aws_access_key():
    text = _lookup_narrative("aws_access_key")
    assert "AWS Access Key" in text


def test_lookup_narrative_aws_secret_key():
    text = _lookup_narrative("aws_secret_key")
    assert "Secret Access Key" in text


def test_lookup_narrative_github_token():
    text = _lookup_narrative("github_token")
    assert "GitHub" in text


def test_lookup_narrative_jwt():
    text = _lookup_narrative("jwt")
    assert "JWT" in text or "JSON Web Token" in text


def test_lookup_narrative_password():
    text = _lookup_narrative("password")
    assert "password" in text.lower()


def test_lookup_narrative_unknown_returns_default():
    text = _lookup_narrative("totally_unknown_pattern_xyz")
    assert text == _DEFAULT_NARRATIVE


def test_lookup_narrative_case_insensitive():
    text = _lookup_narrative("AWS_ACCESS_KEY")
    assert "AWS" in text


# --- _build_recommendations ---

def test_build_recommendations_critical_includes_rotate():
    m = _make_match(severity="critical")
    recs = _build_recommendations(m)
    assert any("Rotate" in r or "revoke" in r for r in recs)


def test_build_recommendations_low_no_rotate():
    m = _make_match(severity="low")
    recs = _build_recommendations(m)
    assert not any("Rotate" in r for r in recs)


def test_build_recommendations_always_includes_remove():
    for sev in ("critical", "high", "medium", "low"):
        m = _make_match(severity=sev)
        recs = _build_recommendations(m)
        assert any("Remove" in r for r in recs)


# --- attach_narrative ---

def test_attach_narrative_returns_narrative_match():
    m = _make_match()
    nm = attach_narrative(m)
    assert isinstance(nm, NarrativeMatch)


def test_attach_narrative_stores_match():
    m = _make_match()
    nm = attach_narrative(m)
    assert nm.match is m


def test_attach_narrative_narrative_is_string():
    m = _make_match()
    nm = attach_narrative(m)
    assert isinstance(nm.narrative, str) and nm.narrative


def test_attach_narrative_override_text():
    m = _make_match()
    nm = attach_narrative(m, narrative="Custom text.")
    assert nm.narrative == "Custom text."


def test_attach_narrative_recommendations_is_list():
    m = _make_match()
    nm = attach_narrative(m)
    assert isinstance(nm.recommendations, list)


def test_attach_narrative_as_dict_keys():
    m = _make_match()
    nm = attach_narrative(m)
    d = nm.as_dict()
    for key in ("pattern_name", "offset", "value", "severity", "narrative", "recommendations"):
        assert key in d


def test_attach_narrative_as_dict_narrative_matches():
    m = _make_match()
    nm = attach_narrative(m)
    assert nm.as_dict()["narrative"] == nm.narrative


# --- attach_narrative_all ---

def test_attach_narrative_all_empty():
    assert attach_narrative_all([]) == []


def test_attach_narrative_all_returns_correct_count():
    matches = [_make_match() for _ in range(4)]
    results = attach_narrative_all(matches)
    assert len(results) == 4


def test_attach_narrative_all_each_is_narrative_match():
    matches = [_make_match(pattern_name="jwt"), _make_match(pattern_name="password")]
    results = attach_narrative_all(matches)
    assert all(isinstance(r, NarrativeMatch) for r in results)
