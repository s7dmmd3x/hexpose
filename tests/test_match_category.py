"""Tests for hexpose.match_category."""
import pytest
from hexpose.scanner import Match
from hexpose.match_category import (
    categorise,
    categorise_match,
    categorise_all,
    group_by_category,
    CategorisedMatch,
    UNKNOWN_CATEGORY,
)


def _make_match(pattern_name: str, value: str = "secret123", offset: int = 0) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity="high")


def test_categorise_aws_key():
    m = _make_match("aws_access_key")
    assert categorise(m) == "cloud"


def test_categorise_github_token():
    m = _make_match("github_token")
    assert categorise(m) == "vcs"


def test_categorise_jwt():
    m = _make_match("jwt_token")
    assert categorise(m) == "auth_token"


def test_categorise_password():
    m = _make_match("password_field")
    assert categorise(m) == "credential"


def test_categorise_rsa_key():
    m = _make_match("rsa_private_key")
    assert categorise(m) == "cryptographic"


def test_categorise_unknown():
    m = _make_match("totally_random_pattern")
    assert categorise(m) == UNKNOWN_CATEGORY


def test_categorise_match_returns_categorised_match():
    m = _make_match("aws_secret")
    cm = categorise_match(m)
    assert isinstance(cm, CategorisedMatch)
    assert cm.match is m
    assert cm.category == "cloud"


def test_categorise_all_returns_list():
    matches = [_make_match("aws_key"), _make_match("github_pat"), _make_match("unknown_thing")]
    result = categorise_all(matches)
    assert len(result) == 3
    assert all(isinstance(r, CategorisedMatch) for r in result)


def test_group_by_category_empty():
    assert group_by_category([]) == {}


def test_group_by_category_groups_correctly():
    matches = [
        _make_match("aws_key"),
        _make_match("gcp_service_account"),
        _make_match("github_token"),
    ]
    groups = group_by_category(matches)
    assert "cloud" in groups
    assert len(groups["cloud"]) == 2
    assert "vcs" in groups
    assert len(groups["vcs"]) == 1


def test_as_dict_contains_category():
    m = _make_match("api_key_prod")
    cm = categorise_match(m)
    d = cm.as_dict()
    assert d["category"] == "api_key"
    assert d["pattern_name"] == "api_key_prod"
    assert "value" in d
    assert "offset" in d
