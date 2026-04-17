"""Tests for hexpose.match_chain and hexpose.chain_builtins."""
import pytest
from hexpose.scanner import Match
from hexpose.match_chain import MatchChain, build_chain
from hexpose.chain_builtins import (
    drop_low_entropy,
    drop_patterns,
    require_min_length,
    uppercase_value,
)


def _m(value="AKIAIOSFODNN7EXAMPLE", pattern="aws_access_key", severity="high", offset=0):
    return Match(pattern_name=pattern, value=value, offset=offset, severity=severity)


def test_empty_chain_passes_match():
    chain = MatchChain()
    m = _m()
    assert chain.run(m) is m


def test_chain_len():
    chain = build_chain(uppercase_value, uppercase_value)
    assert len(chain) == 2


def test_uppercase_value_step():
    chain = build_chain(uppercase_value)
    out = chain.run(_m(value="secret"))
    assert out.value == "SECRET"


def test_drop_low_entropy_removes_simple_value():
    step = drop_low_entropy(min_entropy=3.0)
    chain = build_chain(step)
    assert chain.run(_m(value="aaaaaaaaaa")) is None


def test_drop_low_entropy_keeps_complex_value():
    step = drop_low_entropy(min_entropy=2.0)
    chain = build_chain(step)
    out = chain.run(_m(value="AKIAIOSFODNN7EXAMPLE"))
    assert out is not None


def test_drop_patterns_removes_named_pattern():
    step = drop_patterns({"aws_access_key"})
    chain = build_chain(step)
    assert chain.run(_m(pattern="aws_access_key")) is None


def test_drop_patterns_keeps_other_pattern():
    step = drop_patterns({"other_pattern"})
    chain = build_chain(step)
    assert chain.run(_m(pattern="aws_access_key")) is not None


def test_require_min_length_drops_short():
    step = require_min_length(10)
    chain = build_chain(step)
    assert chain.run(_m(value="short")) is None


def test_require_min_length_keeps_long():
    step = require_min_length(5)
    chain = build_chain(step)
    assert chain.run(_m(value="longenough")) is not None


def test_run_all_filters_list():
    chain = build_chain(drop_patterns({"bad"}))
    matches = [_m(pattern="aws_access_key"), _m(pattern="bad"), _m(pattern="github_token")]
    out = chain.run_all(matches)
    assert len(out) == 2
    assert all(m.pattern_name != "bad" for m in out)


def test_none_short_circuits_remaining_steps():
    calls = []

    def recorder(m):
        calls.append(m)
        return m

    chain = build_chain(drop_patterns({"aws_access_key"}), recorder)
    chain.run(_m(pattern="aws_access_key"))
    assert calls == []


def test_build_chain_returns_match_chain():
    chain = build_chain(uppercase_value)
    assert isinstance(chain, MatchChain)
