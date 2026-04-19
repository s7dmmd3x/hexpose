"""Tests for hexpose.match_checksum."""
import hashlib
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_checksum import (
    ChecksumMatch,
    checksum_match,
    checksum_all,
)


def _make_match(
    value: str = "AKIAIOSFODNN7EXAMPLE",
    pattern_name: str = "aws_access_key",
    severity: str = "high",
    offset: int = 0,
) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


def _make_result(matches: list[Match]) -> ScanResult:
    return ScanResult(source="test", matches=matches)


def test_checksum_match_returns_checksum_match():
    m = _make_match()
    cm = checksum_match(m)
    assert isinstance(cm, ChecksumMatch)


def test_checksum_match_default_algorithm_is_sha256():
    m = _make_match()
    cm = checksum_match(m)
    assert cm.algorithm == "sha256"


def test_checksum_match_sha256_value():
    m = _make_match(value="secret123")
    cm = checksum_match(m, algorithm="sha256")
    expected = hashlib.sha256(b"secret123").hexdigest()
    assert cm.checksum == expected


def test_checksum_match_md5_value():
    m = _make_match(value="secret123")
    cm = checksum_match(m, algorithm="md5")
    expected = hashlib.md5(b"secret123").hexdigest()
    assert cm.checksum == expected


def test_checksum_match_sha1_value():
    m = _make_match(value="secret123")
    cm = checksum_match(m, algorithm="sha1")
    expected = hashlib.sha1(b"secret123").hexdigest()
    assert cm.checksum == expected


def test_checksum_match_unsupported_algorithm_raises():
    m = _make_match()
    with pytest.raises(ValueError, match="Unsupported"):
        checksum_match(m, algorithm="blake2b")


def test_checksum_match_as_dict_keys():
    cm = checksum_match(_make_match())
    d = cm.as_dict()
    assert "algorithm" in d
    assert "checksum" in d
    assert "pattern_name" in d
    assert "value" in d


def test_checksum_match_str_contains_algorithm():
    cm = checksum_match(_make_match())
    assert "sha256" in str(cm)


def test_checksum_match_str_contains_pattern_name():
    cm = checksum_match(_make_match(pattern_name="github_token"))
    assert "github_token" in str(cm)


def test_checksum_all_empty_result():
    result = _make_result([])
    assert checksum_all(result) == []


def test_checksum_all_returns_one_per_match():
    matches = [_make_match(offset=i) for i in range(3)]
    result = _make_result(matches)
    out = checksum_all(result)
    assert len(out) == 3


def test_checksum_all_uses_algorithm():
    matches = [_make_match()]
    result = _make_result(matches)
    out = checksum_all(result, algorithm="md5")
    assert out[0].algorithm == "md5"
