"""Tests for hexpose.scanner and hexpose.patterns."""

import re
from pathlib import Path

import pytest

from hexpose.patterns import load_patterns, SecretPattern
from hexpose.scanner import Scanner, ScanResult, Match


# ---------------------------------------------------------------------------
# Pattern loading
# ---------------------------------------------------------------------------

def test_load_patterns_returns_list():
    patterns = load_patterns()
    assert isinstance(patterns, list)
    assert len(patterns) > 0


def test_all_patterns_are_compiled():
    for p in load_patterns():
        assert isinstance(p.pattern, re.Pattern)


def test_pattern_severity_values():
    valid = {"high", "medium", "low"}
    for p in load_patterns():
        assert p.severity in valid, f"{p.name} has invalid severity '{p.severity}'"


# ---------------------------------------------------------------------------
# Scanner — bytes / text
# ---------------------------------------------------------------------------

def test_scan_bytes_no_match():
    scanner = Scanner()
    result = scanner.scan_bytes(b"nothing sensitive here")
    assert not result.has_findings


def test_scan_bytes_detects_aws_key():
    scanner = Scanner()
    payload = b"export AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
    result = scanner.scan_bytes(payload)
    names = [m.pattern_name for m in result.matches]
    assert "AWS Access Key" in names


def test_scan_bytes_detects_bearer_token():
    scanner = Scanner()
    payload = b"Authorization: Bearer eyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=="
    result = scanner.scan_bytes(payload)
    names = [m.pattern_name for m in result.matches]
    assert "Bearer Token" in names


def test_match_has_correct_offset():
    scanner = Scanner()
    payload = b"   AKIAIOSFODNN7EXAMPLE"
    result = scanner.scan_bytes(payload)
    aws_matches = [m for m in result.matches if m.pattern_name == "AWS Access Key"]
    assert aws_matches
    assert aws_matches[0].offset == 3


def test_match_line_number_multiline():
    scanner = Scanner()
    payload = b"line one\nline two\nAKIAIOSFODNN7EXAMPLE\n"
    result = scanner.scan_bytes(payload)
    aws_matches = [m for m in result.matches if m.pattern_name == "AWS Access Key"]
    assert aws_matches
    assert aws_matches[0].line_number == 3


def test_match_value_truncated():
    scanner = Scanner()
    long_value = "Bearer " + "A" * 200
    result = scanner.scan_bytes(long_value.encode())
    for m in result.matches:
        assert len(m.value) <= 120


# ---------------------------------------------------------------------------
# Scanner — file
# ---------------------------------------------------------------------------

def test_scan_file(tmp_path: Path):
    secret_file = tmp_path / "dump.bin"
    secret_file.write_bytes(b"config: password=supersecret123\n")
    scanner = Scanner()
    result = scanner.scan_file(secret_file)
    assert result.path == str(secret_file)
    assert result.has_findings


def test_scan_file_not_found(tmp_path: Path):
    scanner = Scanner()
    with pytest.raises(IOError):
        scanner.scan_file(tmp_path / "nonexistent.bin")


def test_scan_result_source_name():
    scanner = Scanner()
    result = scanner.scan_bytes(b"nothing", source="my_dump")
    assert result.path == "my_dump"
