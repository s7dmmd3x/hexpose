"""Tests for hexpose.match_compliance and hexpose.compliance_report."""
from __future__ import annotations

import pytest

from hexpose.scanner import Match
from hexpose.match_compliance import (
    ComplianceMatch,
    _lookup_frameworks,
    attach_compliance,
    attach_compliance_all,
)
from hexpose.compliance_report import (
    format_compliance_match,
    format_compliance_report,
    compliance_summary,
)


def _make_match(pattern_name: str = "aws_access_key", value: str = "AKIAIOSFODNN7EXAMPLE") -> Match:
    return Match(
        pattern_name=pattern_name,
        offset=0,
        value=value,
        severity="high",
        line_number=1,
        line="AKIAIOSFODNN7EXAMPLE",
    )


# --- _lookup_frameworks ---

def test_lookup_frameworks_aws():
    fw = _lookup_frameworks("aws_access_key")
    assert "PCI-DSS" in fw
    assert "SOC2" in fw


def test_lookup_frameworks_jwt():
    fw = _lookup_frameworks("jwt_token")
    assert "GDPR" in fw


def test_lookup_frameworks_password():
    fw = _lookup_frameworks("password_field")
    assert "HIPAA" in fw
    assert "GDPR" in fw


def test_lookup_frameworks_unknown_returns_default():
    fw = _lookup_frameworks("totally_unknown_pattern")
    assert fw == ["ISO27001"]


def test_lookup_frameworks_case_insensitive():
    fw = _lookup_frameworks("AWS_SECRET")
    assert "SOC2" in fw


# --- attach_compliance ---

def test_attach_compliance_returns_compliance_match():
    m = _make_match()
    cm = attach_compliance(m)
    assert isinstance(cm, ComplianceMatch)


def test_attach_compliance_stores_match():
    m = _make_match()
    cm = attach_compliance(m)
    assert cm.match is m


def test_attach_compliance_populates_frameworks():
    m = _make_match(pattern_name="aws_access_key")
    cm = attach_compliance(m)
    assert len(cm.frameworks) > 0


def test_attach_compliance_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="jwt_token", value="x.y.z")]
    result = attach_compliance_all(matches)
    assert len(result) == 2
    assert all(isinstance(cm, ComplianceMatch) for cm in result)


# --- as_dict ---

def test_as_dict_contains_required_keys():
    cm = attach_compliance(_make_match())
    d = cm.as_dict()
    for key in ("pattern_name", "offset", "value", "severity", "frameworks"):
        assert key in d


def test_as_dict_frameworks_is_list():
    cm = attach_compliance(_make_match())
    assert isinstance(cm.as_dict()["frameworks"], list)


# --- compliance_report ---

def test_format_compliance_match_contains_pattern_name():
    cm = attach_compliance(_make_match())
    text = format_compliance_match(cm)
    assert "aws_access_key" in text


def test_format_compliance_match_contains_framework():
    cm = attach_compliance(_make_match())
    text = format_compliance_match(cm)
    assert "SOC2" in text or "PCI-DSS" in text


def test_format_compliance_report_empty():
    text = format_compliance_report([])
    assert "No" in text


def test_format_compliance_report_non_empty():
    cms = attach_compliance_all([_make_match()])
    text = format_compliance_report(cms)
    assert "Compliance Report" in text
    assert "aws_access_key" in text


def test_compliance_summary_empty():
    text = compliance_summary([])
    assert "0 matches" in text


def test_compliance_summary_counts_frameworks():
    cms = attach_compliance_all([_make_match()])
    text = compliance_summary(cms)
    assert "1 match" in text
    assert "framework" in text
