"""Tests for hexpose.match_geo."""
import pytest
from hexpose.scanner import Match
from hexpose.match_geo import (
    GeoMatch,
    attach_geo,
    attach_geo_all,
)


def _make_match(pattern_name="aws_key", value="AKIA1234", severity="high") -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=0, severity=severity)


def test_attach_geo_returns_geo_match():
    m = _make_match()
    gm = attach_geo(m, country="US")
    assert isinstance(gm, GeoMatch)


def test_attach_geo_stores_country():
    m = _make_match()
    gm = attach_geo(m, country="DE")
    assert gm.country == "DE"


def test_attach_geo_stores_ip():
    m = _make_match()
    gm = attach_geo(m, ip_address="1.2.3.4")
    assert gm.ip_address == "1.2.3.4"


def test_attach_geo_stores_asn():
    m = _make_match()
    gm = attach_geo(m, asn="AS12345")
    assert gm.asn == "AS12345"


def test_attach_geo_normalises_tags():
    m = _make_match()
    gm = attach_geo(m, tags=["Cloud ", "AWS", ""])
    assert "cloud" in gm.tags
    assert "aws" in gm.tags
    assert "" not in gm.tags


def test_attach_geo_empty_tags_by_default():
    m = _make_match()
    gm = attach_geo(m)
    assert gm.tags == []


def test_as_dict_contains_expected_keys():
    m = _make_match()
    gm = attach_geo(m, country="FR", city="Paris")
    d = gm.as_dict()
    for key in ("pattern_name", "value", "severity", "country", "city", "ip_address", "asn", "tags"):
        assert key in d


def test_as_dict_country_value():
    m = _make_match()
    gm = attach_geo(m, country="JP")
    assert gm.as_dict()["country"] == "JP"


def test_str_with_location():
    m = _make_match()
    gm = attach_geo(m, city="Berlin", country="DE")
    text = str(gm)
    assert "Berlin" in text
    assert "DE" in text


def test_str_unknown_location():
    m = _make_match()
    gm = attach_geo(m)
    assert "unknown location" in str(gm)


def test_attach_geo_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="github_token", value="ghp_abc")]
    result = attach_geo_all(matches, country="US")
    assert len(result) == 2
    assert all(isinstance(r, GeoMatch) for r in result)


def test_attach_geo_all_applies_kwargs():
    matches = [_make_match()]
    result = attach_geo_all(matches, country="CA", city="Toronto")
    assert result[0].country == "CA"
    assert result[0].city == "Toronto"
