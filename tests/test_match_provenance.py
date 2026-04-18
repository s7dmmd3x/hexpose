"""Tests for hexpose.match_provenance."""
import pytest
from hexpose.scanner import Match, ScanResult
from hexpose.match_provenance import (
    ProvenanceMatch,
    attach_provenance,
    attach_provenance_all,
)


def _make_match(name="aws_key", value="AKIAIOSFODNN7EXAMPLE", offset=0) -> Match:
    return Match(pattern_name=name, value=value, offset=offset, severity="high")


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test.bin", matches=matches or [])


def test_attach_provenance_returns_provenance_match():
    m = _make_match()
    pm = attach_provenance(m, source_file="dump.bin")
    assert isinstance(pm, ProvenanceMatch)


def test_attach_provenance_stores_source_file():
    m = _make_match()
    pm = attach_provenance(m, source_file="firmware.bin")
    assert pm.source_file == "firmware.bin"


def test_attach_provenance_default_tool_name():
    m = _make_match()
    pm = attach_provenance(m, source_file="x")
    assert pm.scan_tool == "hexpose"


def test_attach_provenance_custom_tool_and_version():
    m = _make_match()
    pm = attach_provenance(m, source_file="x", scan_tool="mytool", scan_version="2.0")
    assert pm.scan_tool == "mytool"
    assert pm.scan_version == "2.0"


def test_attach_provenance_command_line():
    m = _make_match()
    pm = attach_provenance(m, source_file="x", command_line="hexpose scan dump.bin")
    assert pm.command_line == "hexpose scan dump.bin"


def test_attach_provenance_extra_kwargs():
    m = _make_match()
    pm = attach_provenance(m, source_file="x", pipeline="ci", build="42")
    assert pm.extra["pipeline"] == "ci"
    assert pm.extra["build"] == "42"


def test_as_dict_contains_expected_keys():
    m = _make_match()
    pm = attach_provenance(m, source_file="a.bin", scan_version="1.2.3")
    d = pm.as_dict()
    for key in ("pattern_name", "offset", "value", "source_file", "scan_tool", "scan_version"):
        assert key in d


def test_as_dict_value_matches_match():
    m = _make_match(value="SECRET123")
    pm = attach_provenance(m, source_file="b.bin")
    assert pm.as_dict()["value"] == "SECRET123"


def test_attach_provenance_all_empty_result():
    result = _make_result()
    pms = attach_provenance_all(result, source_file="empty.bin")
    assert pms == []


def test_attach_provenance_all_returns_one_per_match():
    result = _make_result([_make_match(), _make_match(name="github_token", value="ghp_abc")])
    pms = attach_provenance_all(result, source_file="multi.bin")
    assert len(pms) == 2


def test_attach_provenance_all_propagates_source_file():
    result = _make_result([_make_match()])
    pms = attach_provenance_all(result, source_file="target.bin")
    assert all(pm.source_file == "target.bin" for pm in pms)
