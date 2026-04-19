"""Tests for hexpose.match_ownership."""
import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_ownership import (
    OwnershipMatch,
    attach_ownership,
    attach_ownership_all,
)


def _make_match(pattern_name="aws_key", value="AKIA1234", severity="critical"):
    return Match(pattern_name=pattern_name, value=value, offset=0, severity=severity)


def _make_result(matches=None):
    return ScanResult(source="test.bin", matches=matches or [])


def test_attach_ownership_returns_ownership_match():
    m = _make_match()
    om = attach_ownership(m)
    assert isinstance(om, OwnershipMatch)


def test_attach_ownership_default_owner():
    om = attach_ownership(_make_match())
    assert om.owner == "unknown"


def test_attach_ownership_stores_owner():
    om = attach_ownership(_make_match(), owner="alice")
    assert om.owner == "alice"


def test_attach_ownership_strips_whitespace():
    om = attach_ownership(_make_match(), owner="  bob  ", team="  ops  ")
    assert om.owner == "bob"
    assert om.team == "ops"


def test_attach_ownership_empty_owner_falls_back_to_unknown():
    om = attach_ownership(_make_match(), owner="   ")
    assert om.owner == "unknown"


def test_attach_ownership_stores_contact():
    om = attach_ownership(_make_match(), contact="security@example.com")
    assert om.contact == "security@example.com"


def test_attach_ownership_stores_tags():
    om = attach_ownership(_make_match(), tags=["pci", "gdpr"])
    assert "pci" in om.tags
    assert "gdpr" in om.tags


def test_attach_ownership_filters_empty_tags():
    om = attach_ownership(_make_match(), tags=["pci", "", "  "])
    assert om.tags == ["pci"]


def test_as_dict_contains_required_keys():
    om = attach_ownership(_make_match(), owner="carol", team="infra")
    d = om.as_dict()
    for key in ("pattern_name", "value", "severity", "owner", "team", "contact", "tags"):
        assert key in d


def test_as_dict_owner_value():
    om = attach_ownership(_make_match(), owner="dave")
    assert om.as_dict()["owner"] == "dave"


def test_str_contains_owner():
    om = attach_ownership(_make_match(), owner="eve")
    assert "eve" in str(om)


def test_attach_ownership_all_returns_list():
    result = _make_result([_make_match(), _make_match(pattern_name="github_token")])
    items = attach_ownership_all(result, owner="team-a", team="security")
    assert len(items) == 2
    assert all(isinstance(i, OwnershipMatch) for i in items)


def test_attach_ownership_all_empty_result():
    result = _make_result([])
    items = attach_ownership_all(result)
    assert items == []


def test_attach_ownership_all_propagates_owner():
    result = _make_result([_make_match(), _make_match()])
    items = attach_ownership_all(result, owner="frank")
    assert all(i.owner == "frank" for i in items)
