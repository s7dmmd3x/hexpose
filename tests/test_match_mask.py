"""Tests for hexpose.match_mask."""
import pytest
from hexpose.scanner import Match
from hexpose.match_mask import MaskedMatch, mask_match, mask_all


def _make_match(
    value: str = "AKIAIOSFODNN7EXAMPLE",
    pattern_name: str = "aws_access_key",
    severity: str = "critical",
    offset: int = 0,
) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


def test_mask_match_returns_masked_match():
    m = _make_match()
    mm = mask_match(m)
    assert isinstance(mm, MaskedMatch)


def test_mask_match_partial_mode_default():
    m = _make_match(value="AKIAIOSFODNN7EXAMPLE")
    mm = mask_match(m, mode="partial")
    assert mm.mask_mode == "partial"
    assert mm.masked_value != m.value


def test_mask_match_full_mode_placeholder():
    m = _make_match(value="supersecret")
    mm = mask_match(m, mode="full")
    assert mm.mask_mode == "full"
    assert mm.masked_value == "[REDACTED]"


def test_mask_match_full_reveal_chars_zero():
    m = _make_match()
    mm = mask_match(m, mode="full")
    assert mm.reveal_chars == 0


def test_mask_match_partial_reveal_chars_stored():
    m = _make_match()
    mm = mask_match(m, mode="partial", reveal_chars=6)
    assert mm.reveal_chars == 6


def test_mask_match_invalid_mode_raises():
    m = _make_match()
    with pytest.raises(ValueError, match="Unknown mask mode"):
        mask_match(m, mode="scramble")


def test_mask_match_as_dict_keys():
    m = _make_match()
    d = mask_match(m).as_dict()
    for key in ("pattern_name", "masked_value", "mask_mode", "reveal_chars", "offset", "severity"):
        assert key in d


def test_mask_match_str_contains_pattern_name():
    m = _make_match(pattern_name="jwt_token")
    mm = mask_match(m)
    assert "jwt_token" in str(mm)


def test_mask_all_returns_list_of_masked_matches():
    matches = [_make_match(offset=i) for i in range(3)]
    result = mask_all(matches)
    assert len(result) == 3
    assert all(isinstance(x, MaskedMatch) for x in result)


def test_mask_all_empty_list():
    assert mask_all([]) == []


def test_mask_all_mode_propagated():
    matches = [_make_match(), _make_match(value="anothersecret")]
    result = mask_all(matches, mode="full")
    assert all(mm.mask_mode == "full" for mm in result)
