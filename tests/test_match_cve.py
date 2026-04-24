"""Tests for hexpose.match_cve."""
from __future__ import annotations

import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_cve import (
    CVEMatch,
    attach_cve,
    attach_cve_all,
    _lookup_cves,
)


def _make_match(
    pattern_name: str = "aws_access_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    severity: str = "high",
    offset: int = 0,
) -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        severity=severity,
        offset=offset,
    )


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test", matches=matches or [])


# --- _lookup_cves ---

def test_lookup_cves_aws_keyword():
    cves = _lookup_cves("aws_access_key")
    assert len(cves) > 0
    assert all(c.startswith("CVE-") for c in cves)


def test_lookup_cves_unknown_returns_empty():
    assert _lookup_cves("totally_unknown_pattern") == []


def test_lookup_cves_case_insensitive():
    lower = _lookup_cves("aws_key")
    upper = _lookup_cves("AWS_KEY")
    assert lower == upper


# --- attach_cve ---

def test_attach_cve_returns_cve_match():
    m = _make_match()
    result = attach_cve(m)
    assert isinstance(result, CVEMatch)


def test_attach_cve_stores_match():
    m = _make_match()
    cm = attach_cve(m)
    assert cm.match is m


def test_attach_cve_aws_pattern_has_cves():
    m = _make_match(pattern_name="aws_access_key")
    cm = attach_cve(m)
    assert len(cm.cves) > 0


def test_attach_cve_unknown_pattern_empty_cves():
    m = _make_match(pattern_name="mystery_token")
    cm = attach_cve(m)
    assert cm.cves == []


def test_attach_cve_extra_cves_appended():
    m = _make_match(pattern_name="mystery_token")
    cm = attach_cve(m, extra_cves=["CVE-2023-99999"])
    assert "CVE-2023-99999" in cm.cves


def test_attach_cve_extra_cves_deduped():
    m = _make_match(pattern_name="aws_access_key")
    existing = _lookup_cves("aws_access_key")
    cm = attach_cve(m, extra_cves=existing)
    assert len(cm.cves) == len(set(cm.cves))


def test_attach_cve_reference_url_stored():
    m = _make_match()
    cm = attach_cve(m, reference_url="https://nvd.nist.gov")
    assert cm.reference_url == "https://nvd.nist.gov"


def test_attach_cve_reference_url_default_none():
    m = _make_match()
    cm = attach_cve(m)
    assert cm.reference_url is None


# --- as_dict ---

def test_as_dict_contains_cves_key():
    m = _make_match()
    cm = attach_cve(m)
    d = cm.as_dict()
    assert "cves" in d


def test_as_dict_contains_reference_url_key():
    m = _make_match()
    cm = attach_cve(m)
    d = cm.as_dict()
    assert "cve_reference_url" in d


# --- __str__ ---

def test_str_with_cves_contains_cve_id():
    m = _make_match(pattern_name="aws_access_key")
    cm = attach_cve(m)
    assert "CVE-" in str(cm)


def test_str_without_cves_says_none():
    m = _make_match(pattern_name="mystery_token")
    cm = attach_cve(m)
    assert "none" in str(cm)


# --- attach_cve_all ---

def test_attach_cve_all_returns_list():
    r = _make_result([_make_match(), _make_match(pattern_name="github_token")])
    results = attach_cve_all(r)
    assert isinstance(results, list)
    assert len(results) == 2


def test_attach_cve_all_empty_result():
    r = _make_result([])
    assert attach_cve_all(r) == []


def test_attach_cve_all_all_are_cve_matches():
    r = _make_result([_make_match(), _make_match()])
    for cm in attach_cve_all(r):
        assert isinstance(cm, CVEMatch)
