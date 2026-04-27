"""Tests for hexpose.match_snapshot and hexpose.snapshot_report."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hexpose.match_snapshot import (
    Snapshot,
    SnapshotEntry,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
    take_snapshot,
)
from hexpose.snapshot_report import (
    format_diff_report,
    format_snapshot_report,
    snapshot_summary,
)


def _make_match(pattern_name="aws_key", value="AKIA1234567890ABCDEF", offset=0, severity="high"):
    from hexpose.scanner import Match
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


def _make_result(matches=None):
    from hexpose.scanner import ScanResult
    return ScanResult(source="test", matches=matches or [])


# --- SnapshotEntry ---

def test_snapshot_entry_from_match():
    m = _make_match()
    e = SnapshotEntry.from_match(m)
    assert e.pattern_name == m.pattern_name
    assert e.value == m.value
    assert e.offset == m.offset
    assert e.severity == m.severity


def test_snapshot_entry_as_dict_keys():
    e = SnapshotEntry("aws_key", "AKIAVAL", 0, "high")
    d = e.as_dict()
    assert set(d) == {"pattern_name", "value", "offset", "severity"}


def test_snapshot_entry_roundtrip():
    e = SnapshotEntry("jwt", "token.val.sig", 42, "medium")
    assert SnapshotEntry.from_dict(e.as_dict()) == e


# --- Snapshot ---

def test_take_snapshot_empty():
    snap = take_snapshot([])
    assert snap.entries == []
    assert isinstance(snap.taken_at, datetime)


def test_take_snapshot_counts_matches():
    r1 = _make_result([_make_match(), _make_match(pattern_name="jwt")])
    r2 = _make_result([_make_match(pattern_name="github_token")])
    snap = take_snapshot([r1, r2])
    assert len(snap.entries) == 3


def test_snapshot_as_dict_has_taken_at():
    snap = take_snapshot([])
    d = snap.as_dict()
    assert "taken_at" in d
    assert "entries" in d


def test_snapshot_roundtrip():
    r = _make_result([_make_match()])
    snap = take_snapshot([r])
    snap2 = Snapshot.from_dict(snap.as_dict())
    assert len(snap2.entries) == 1
    assert snap2.entries[0].pattern_name == "aws_key"


# --- save / load ---

def test_save_and_load_snapshot(tmp_path):
    p = tmp_path / "snap.json"
    snap = take_snapshot([_make_result([_make_match()])])
    save_snapshot(snap, p)
    loaded = load_snapshot(p)
    assert loaded is not None
    assert len(loaded.entries) == 1


def test_load_snapshot_missing_file(tmp_path):
    result = load_snapshot(tmp_path / "nonexistent.json")
    assert result is None


# --- diff ---

def test_diff_no_changes():
    snap = take_snapshot([_make_result([_make_match()])])
    added, removed = diff_snapshots(snap, snap)
    assert added == []
    assert removed == []


def test_diff_detects_added():
    old = take_snapshot([])
    new = take_snapshot([_make_result([_make_match()])])
    added, removed = diff_snapshots(old, new)
    assert len(added) == 1
    assert removed == []


def test_diff_detects_removed():
    old = take_snapshot([_make_result([_make_match()])])
    new = take_snapshot([])
    added, removed = diff_snapshots(old, new)
    assert added == []
    assert len(removed) == 1


# --- report ---

def test_format_snapshot_report_contains_pattern_name():
    snap = take_snapshot([_make_result([_make_match()])])
    report = format_snapshot_report(snap)
    assert "aws_key" in report


def test_format_diff_report_no_changes():
    report = format_diff_report([], [])
    assert "No changes" in report


def test_format_diff_report_shows_added():
    e = SnapshotEntry("aws_key", "AKIAVAL", 0, "high")
    report = format_diff_report([e], [])
    assert "aws_key" in report


def test_snapshot_summary_contains_count():
    snap = take_snapshot([_make_result([_make_match(), _make_match()])])
    s = snapshot_summary(snap)
    assert "2" in s
