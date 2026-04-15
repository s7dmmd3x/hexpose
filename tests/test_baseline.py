"""Tests for hexpose.baseline."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from hexpose.baseline import diff_baseline, load_baseline_fingerprints, save_baseline
from hexpose.scanner import Match, ScanResult
from hexpose.suppress import _fingerprint


def _make_match(value="AKIAIOSFODNN7EXAMPLE", pattern_name="aws_access_key") -> Match:
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=0,
        severity="high",
        entropy=3.8,
        context=b"",
    )


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test.bin", matches=matches or [])


def test_save_baseline_creates_file():
    result = _make_result([_make_match()])
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    save_baseline(result, path)
    data = json.loads(Path(path).read_text())
    assert data["source"] == "test.bin"
    assert len(data["matches"]) == 1


def test_save_baseline_stores_fingerprint():
    m = _make_match()
    result = _make_result([m])
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    save_baseline(result, path)
    fps = load_baseline_fingerprints(path)
    assert _fingerprint(m) in fps


def test_load_baseline_fingerprints_missing_file():
    fps = load_baseline_fingerprints("/tmp/no_such_baseline.json")
    assert fps == set()


def test_diff_baseline_new_match():
    m_old = _make_match(value="OLD_SECRET")
    m_new = _make_match(value="NEW_SECRET")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    save_baseline(_make_result([m_old]), path)
    new_matches, resolved = diff_baseline(_make_result([m_new]), path)
    assert m_new in new_matches
    assert _fingerprint(m_old) in resolved


def test_diff_baseline_no_changes():
    m = _make_match()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    save_baseline(_make_result([m]), path)
    new_matches, resolved = diff_baseline(_make_result([m]), path)
    assert new_matches == []
    assert resolved == []


def test_diff_baseline_all_resolved():
    m = _make_match()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    save_baseline(_make_result([m]), path)
    new_matches, resolved = diff_baseline(_make_result([]), path)
    assert new_matches == []
    assert _fingerprint(m) in resolved
