"""Tests for hexpose.match_cluster_report."""

from __future__ import annotations

import pytest

from hexpose.scanner import Match
from hexpose.match_cluster import cluster_by_pattern
from hexpose.match_cluster_report import (
    format_cluster,
    format_cluster_report,
    cluster_summary,
)


def _make_match(pattern_name: str, value: str, offset: int = 0) -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity="high",
    )


# ---------------------------------------------------------------------------
# format_cluster
# ---------------------------------------------------------------------------

def test_format_cluster_contains_pattern_name():
    m = _make_match("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
    clusters = cluster_by_pattern([m])
    output = format_cluster(clusters[0], colour=False)
    assert "aws_access_key" in output


def test_format_cluster_contains_match_count():
    matches = [_make_match("jwt", "token.value.sig", i) for i in range(3)]
    clusters = cluster_by_pattern(matches)
    output = format_cluster(clusters[0], colour=False)
    assert "3" in output


def test_format_cluster_contains_value_preview():
    m = _make_match("github_token", "ghp_abc123")
    clusters = cluster_by_pattern([m])
    output = format_cluster(clusters[0], colour=False)
    assert "ghp_abc123" in output


def test_format_cluster_truncates_long_value():
    long_value = "x" * 80
    m = _make_match("generic_secret", long_value)
    clusters = cluster_by_pattern([m])
    output = format_cluster(clusters[0], colour=False)
    assert "..." in output


def test_format_cluster_colour_wraps_header():
    m = _make_match("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
    clusters = cluster_by_pattern([m])
    output_colour = format_cluster(clusters[0], colour=True)
    assert "\033[" in output_colour


# ---------------------------------------------------------------------------
# format_cluster_report
# ---------------------------------------------------------------------------

def test_format_cluster_report_empty():
    result = format_cluster_report([], colour=False)
    assert "No clusters" in result


def test_format_cluster_report_single_cluster():
    m = _make_match("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
    clusters = cluster_by_pattern([m])
    output = format_cluster_report(clusters, colour=False)
    assert "aws_access_key" in output


def test_format_cluster_report_multiple_clusters_has_divider():
    matches = [
        _make_match("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
        _make_match("github_token", "ghp_abc123"),
    ]
    clusters = cluster_by_pattern(matches)
    output = format_cluster_report(clusters, colour=False)
    assert "-" * 20 in output  # divider is 60 dashes


# ---------------------------------------------------------------------------
# cluster_summary
# ---------------------------------------------------------------------------

def test_cluster_summary_empty():
    summary = cluster_summary([])
    assert "0" in summary
    assert "none" in summary


def test_cluster_summary_counts_clusters():
    matches = [
        _make_match("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
        _make_match("github_token", "ghp_abc123"),
    ]
    clusters = cluster_by_pattern(matches)
    summary = cluster_summary(clusters)
    assert "2" in summary


def test_cluster_summary_lists_pattern_names():
    matches = [
        _make_match("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
        _make_match("github_token", "ghp_abc123"),
    ]
    clusters = cluster_by_pattern(matches)
    summary = cluster_summary(clusters)
    assert "aws_access_key" in summary
    assert "github_token" in summary
