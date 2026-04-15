"""Tests for hexpose.reporter."""

from __future__ import annotations

import io
import json

import pytest

from hexpose.reporter import Reporter
from hexpose.scanner import Match, ScanResult


def _make_result(num_matches: int = 0) -> ScanResult:
    matches = [
        Match(
            pattern_name="aws_access_key",
            severity="high",
            offset=16 * i,
            value=f"AKIA{'X' * 16}{i}",
            context=f"...context{i}...",
        )
        for i in range(num_matches)
    ]
    return ScanResult(source="test.bin", total_bytes=1024, matches=matches)


def test_reporter_invalid_format():
    with pytest.raises(ValueError, match="Unsupported format"):
        Reporter(fmt="xml")


def test_text_no_matches():
    buf = io.StringIO()
    r = Reporter(fmt="text", stream=buf, color=False)
    r.report(_make_result(0))
    out = buf.getvalue()
    assert "No secrets found" in out
    assert "test.bin" in out


def test_text_with_matches():
    buf = io.StringIO()
    r = Reporter(fmt="text", stream=buf, color=False)
    r.report(_make_result(2))
    out = buf.getvalue()
    assert "aws_access_key" in out
    assert "[HIGH]" in out
    assert "Total matches: 2" in out


def test_json_no_matches():
    buf = io.StringIO()
    r = Reporter(fmt="json", stream=buf)
    r.report(_make_result(0))
    data = json.loads(buf.getvalue())
    assert data["source"] == "test.bin"
    assert data["matches"] == []
    assert data["total_bytes"] == 1024


def test_json_with_matches():
    buf = io.StringIO()
    r = Reporter(fmt="json", stream=buf)
    r.report(_make_result(3))
    data = json.loads(buf.getvalue())
    assert len(data["matches"]) == 3
    first = data["matches"][0]
    assert "pattern_name" in first
    assert "severity" in first
    assert "offset" in first
    assert "value" in first


def test_text_color_codes_present():
    buf = io.StringIO()
    r = Reporter(fmt="text", stream=buf, color=True)
    r.report(_make_result(1))
    out = buf.getvalue()
    # ANSI escape sequences should be present
    assert "\033[" in out
