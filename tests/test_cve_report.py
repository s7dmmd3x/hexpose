"""Tests for hexpose.cve_report."""
from __future__ import annotations

from hexpose.scanner import Match
from hexpose.match_cve import CVEMatch, attach_cve
from hexpose.cve_report import (
    format_cve_match,
    format_cve_report,
    cve_summary,
)


def _make_cm(
    pattern_name: str = "aws_access_key",
    severity: str = "high",
    cves=None,
    reference_url=None,
) -> CVEMatch:
    m = Match(
        pattern_name=pattern_name,
        value="AKIAIOSFODNN7EXAMPLE",
        severity=severity,
        offset=0,
    )
    return CVEMatch(
        match=m,
        cves=cves if cves is not None else ["CVE-2020-15228"],
        reference_url=reference_url,
    )


def test_format_cve_match_contains_pattern_name():
    cm = _make_cm()
    assert "aws_access_key" in format_cve_match(cm)


def test_format_cve_match_contains_severity():
    cm = _make_cm(severity="critical")
    assert "critical" in format_cve_match(cm)


def test_format_cve_match_contains_cve_id():
    cm = _make_cm(cves=["CVE-2020-15228"])
    assert "CVE-2020-15228" in format_cve_match(cm)


def test_format_cve_match_no_cves_says_none():
    cm = _make_cm(cves=[])
    assert "no CVEs" in format_cve_match(cm)


def test_format_cve_match_includes_reference_url():
    cm = _make_cm(reference_url="https://nvd.nist.gov")
    assert "https://nvd.nist.gov" in format_cve_match(cm)


def test_format_cve_report_empty():
    out = format_cve_report([])
    assert "No CVE" in out


def test_format_cve_report_contains_header():
    cms = [_make_cm()]
    out = format_cve_report(cms)
    assert "CVE Report" in out


def test_format_cve_report_contains_match_line():
    cms = [_make_cm()]
    out = format_cve_report(cms)
    assert "aws_access_key" in out


def test_cve_summary_counts_matches():
    cms = [_make_cm(), _make_cm(pattern_name="github_token", cves=["CVE-2021-41599"])]
    summary = cve_summary(cms)
    assert "2" in summary


def test_cve_summary_unique_cve_count():
    cms = [
        _make_cm(cves=["CVE-2020-15228"]),
        _make_cm(cves=["CVE-2020-15228", "CVE-2021-41599"]),
    ]
    summary = cve_summary(cms)
    # 2 unique CVEs
    assert "2" in summary
