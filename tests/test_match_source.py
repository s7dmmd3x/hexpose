"""Tests for hexpose.match_source."""
from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

import pytest

from hexpose.match_source import (
    SourcedMatch,
    _sha256_of,
    source_all,
    source_match,
)


def _make_match(name="aws_access_key", value="AKIAIOSFODNN7EXAMPLE", offset=0, severity="high"):
    m = MagicMock()
    m.pattern_name = name
    m.value = value
    m.offset = offset
    m.severity = severity
    return m


# ---------------------------------------------------------------------------
# _sha256_of
# ---------------------------------------------------------------------------

def test_sha256_of_known_value():
    data = b"hello"
    expected = hashlib.sha256(data).hexdigest()
    assert _sha256_of(data) == expected


def test_sha256_of_empty():
    expected = hashlib.sha256(b"").hexdigest()
    assert _sha256_of(b"") == expected


# ---------------------------------------------------------------------------
# source_match — raw_bytes path
# ---------------------------------------------------------------------------

def test_source_match_with_raw_bytes_sets_size():
    m = _make_match()
    raw = b"A" * 128
    sm = source_match(m, source_type="memory_dump", raw_bytes=raw)
    assert sm.file_size == 128


def test_source_match_with_raw_bytes_sets_sha256():
    m = _make_match()
    raw = b"secret_data"
    sm = source_match(m, raw_bytes=raw)
    assert sm.sha256 == _sha256_of(raw)


def test_source_match_preserves_source_type():
    m = _make_match()
    sm = source_match(m, source_type="stdin", raw_bytes=b"x")
    assert sm.source_type == "stdin"


def test_source_match_no_bytes_no_path_gives_none_fields():
    m = _make_match()
    sm = source_match(m)
    assert sm.file_size is None
    assert sm.sha256 is None


def test_source_match_returns_sourced_match_instance():
    m = _make_match()
    sm = source_match(m, raw_bytes=b"data")
    assert isinstance(sm, SourcedMatch)
    assert sm.match is m


# ---------------------------------------------------------------------------
# source_match — file path
# ---------------------------------------------------------------------------

def test_source_match_with_real_file(tmp_path):
    content = b"binary content here"
    f = tmp_path / "dump.bin"
    f.write_bytes(content)
    m = _make_match()
    sm = source_match(m, source_path=str(f), source_type="file")
    assert sm.file_size == len(content)
    assert sm.sha256 == _sha256_of(content)
    assert sm.source_path == str(f)


def test_source_match_missing_file_gives_none_fields(tmp_path):
    m = _make_match()
    sm = source_match(m, source_path=str(tmp_path / "nonexistent.bin"), source_type="file")
    assert sm.file_size is None
    assert sm.sha256 is None


# ---------------------------------------------------------------------------
# as_dict
# ---------------------------------------------------------------------------

def test_as_dict_contains_expected_keys():
    m = _make_match()
    sm = source_match(m, source_type="file", raw_bytes=b"sample")
    d = sm.as_dict()
    for key in ("pattern_name", "value", "offset", "severity", "source_type", "file_size", "sha256"):
        assert key in d, f"Missing key: {key}"


def test_as_dict_values_match_fields():
    m = _make_match(name="github_token", value="ghp_abc123", offset=42, severity="critical")
    raw = b"payload"
    sm = source_match(m, source_type="memory_dump", raw_bytes=raw)
    d = sm.as_dict()
    assert d["pattern_name"] == "github_token"
    assert d["value"] == "ghp_abc123"
    assert d["offset"] == 42
    assert d["severity"] == "critical"
    assert d["source_type"] == "memory_dump"
    assert d["file_size"] == len(raw)
    assert d["sha256"] == _sha256_of(raw)
