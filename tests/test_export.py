"""Tests for hexpose.export."""

import csv
import io
import json

import pytest

from hexpose.export import to_json, to_csv, to_sarif, export
from hexpose.scanner import ScanResult, Match


def _make_match(value: str = "AKIAIOSFODNN7EXAMPLE") -> Match:
    return Match(
        pattern_name="aws_access_key",
        severity="high",
        offset=0,
        value=value,
        entropy=3.8,
    )


def _make_result(n: int = 1) -> ScanResult:
    return ScanResult(
        source="test.bin",
        format="elf",
        matches=[_make_match() for _ in range(n)],
    )


def test_to_json_structure():
    data = json.loads(to_json(_make_result()))
    assert data["source"] == "test.bin"
    assert len(data["matches"]) == 1
    assert data["matches"][0]["pattern"] == "aws_access_key"


def test_to_json_redacts_value():
    data = json.loads(to_json(_make_result(), redact=True))
    assert "AKIAIOSFODNN7EXAMPLE" not in data["matches"][0]["value"]


def test_to_json_no_redact():
    data = json.loads(to_json(_make_result(), redact=False))
    assert data["matches"][0]["value"] == "AKIAIOSFODNN7EXAMPLE"


def test_to_json_no_matches():
    result = ScanResult(source="empty.bin", format="raw", matches=[])
    data = json.loads(to_json(result))
    assert data["matches"] == []


def test_to_csv_has_header_and_row():
    text = to_csv(_make_result())
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["source"] == "test.bin"
    assert rows[0]["pattern"] == "aws_access_key"


def test_to_csv_redacts():
    text = to_csv(_make_result(), redact=True)
    assert "AKIAIOSFODNN7EXAMPLE" not in text


def test_to_sarif_valid_structure():
    data = json.loads(to_sarif(_make_result()))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "hexpose"
    assert len(run["results"]) == 1


def test_export_unknown_format_raises():
    with pytest.raises(ValueError, match="Unknown export format"):
        export(_make_result(), fmt="xml")


def test_export_delegates_to_json():
    out = export(_make_result(), fmt="json", redact=False)
    data = json.loads(out)
    assert data["source"] == "test.bin"


def test_export_delegates_to_csv():
    out = export(_make_result(), fmt="csv", redact=False)
    assert "aws_access_key" in out


def test_export_delegates_to_sarif():
    out = export(_make_result(), fmt="sarif", redact=False)
    data = json.loads(out)
    assert "runs" in data
