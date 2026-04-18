"""Tests for hexpose.match_origin."""
import pytest
from hexpose.scanner import Match, ScanResult
from hexpose.match_origin import OriginMatch, attach_origin, attach_origin_all


def _make_match(
    pattern_name: str = "aws_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    offset: int = 0,
    severity: str = "high",
) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


def _make_result(matches=None) -> ScanResult:
    return ScanResult(source="test.bin", matches=matches or [])


def test_attach_origin_returns_origin_match():
    m = _make_match()
    om = attach_origin(m)
    assert isinstance(om, OriginMatch)


def test_attach_origin_stores_host():
    om = attach_origin(_make_match(), host="prod-server-1")
    assert om.host == "prod-server-1"


def test_attach_origin_stores_environment():
    om = attach_origin(_make_match(), environment="production")
    assert om.environment == "production"


def test_attach_origin_stores_region():
    om = attach_origin(_make_match(), region="us-east-1")
    assert om.region == "us-east-1"


def test_attach_origin_stores_tags():
    om = attach_origin(_make_match(), tags=["ci", "nightly"])
    assert "ci" in om.tags
    assert "nightly" in om.tags


def test_attach_origin_defaults_are_none():
    om = attach_origin(_make_match())
    assert om.host is None
    assert om.environment is None
    assert om.region is None
    assert om.tags == []


def test_as_dict_contains_expected_keys():
    om = attach_origin(_make_match(), host="h", environment="e", region="r", tags=["t"])
    d = om.as_dict()
    for key in ("pattern_name", "value", "offset", "severity", "host", "environment", "region", "tags"):
        assert key in d


def test_as_dict_values_match():
    m = _make_match(value="secret123")
    om = attach_origin(m, host="myhost", environment="staging", region="eu-west-1")
    d = om.as_dict()
    assert d["value"] == "secret123"
    assert d["host"] == "myhost"
    assert d["environment"] == "staging"
    assert d["region"] == "eu-west-1"


def test_str_contains_pattern_name():
    om = attach_origin(_make_match(pattern_name="github_token"))
    assert "github_token" in str(om)


def test_str_contains_host_when_set():
    om = attach_origin(_make_match(), host="build-agent")
    assert "build-agent" in str(om)


def test_str_omits_none_fields():
    om = attach_origin(_make_match())
    assert "host=" not in str(om)
    assert "env=" not in str(om)


def test_attach_origin_all_returns_list():
    result = _make_result([_make_match(), _make_match(pattern_name="jwt")])
    origins = attach_origin_all(result, host="server")
    assert len(origins) == 2
    assert all(isinstance(o, OriginMatch) for o in origins)


def test_attach_origin_all_empty_result():
    result = _make_result([])
    origins = attach_origin_all(result)
    assert origins == []


def test_tags_list_is_copied():
    tags = ["a", "b"]
    om = attach_origin(_make_match(), tags=tags)
    tags.append("c")
    assert "c" not in om.tags
