"""Tests for match_environment and environment_report."""
from __future__ import annotations

import pytest

from hexpose.scanner import Match, ScanResult
from hexpose.match_environment import (
    EnvironmentMatch,
    attach_environment,
    attach_environment_all,
)
from hexpose.environment_report import (
    format_environment_match,
    format_environment_report,
    environment_summary,
)


def _make_match(pattern_name="aws_key", value="AKIA1234", severity="high", offset=0):
    return Match(pattern_name=pattern_name, value=value, severity=severity, offset=offset)


def _make_result(matches=None):
    return ScanResult(source="test.bin", matches=matches or [])


def test_attach_environment_returns_environment_match():
    m = _make_match()
    em = attach_environment(m)
    assert isinstance(em, EnvironmentMatch)


def test_attach_environment_default_env_name():
    em = attach_environment(_make_match())
    assert em.env_name == "unknown"


def test_attach_environment_stores_env_name():
    em = attach_environment(_make_match(), env_name="production")
    assert em.env_name == "production"


def test_attach_environment_stores_region():
    em = attach_environment(_make_match(), region="us-east-1")
    assert em.region == "us-east-1"


def test_attach_environment_stores_team():
    em = attach_environment(_make_match(), team="platform")
    assert em.team == "platform"


def test_attach_environment_stores_tags():
    em = attach_environment(_make_match(), tags=["ci", "prod"])
    assert "ci" in em.tags
    assert "prod" in em.tags


def test_attach_environment_tags_default_empty():
    em = attach_environment(_make_match())
    assert em.tags == []


def test_as_dict_contains_env_name():
    em = attach_environment(_make_match(), env_name="staging")
    d = em.as_dict()
    assert d["env_name"] == "staging"


def test_as_dict_contains_pattern_name():
    em = attach_environment(_make_match(pattern_name="github_token"))
    assert em.as_dict()["pattern_name"] == "github_token"


def test_str_contains_env_name():
    em = attach_environment(_make_match(), env_name="dev")
    assert "dev" in str(em)


def test_attach_environment_all_returns_list():
    result = _make_result([_make_match(), _make_match(pattern_name="jwt")])
    items = attach_environment_all(result, env_name="prod")
    assert len(items) == 2
    assert all(isinstance(i, EnvironmentMatch) for i in items)


def test_attach_environment_all_empty_result():
    result = _make_result([])
    assert attach_environment_all(result) == []


def test_format_environment_match_contains_env():
    em = attach_environment(_make_match(), env_name="production")
    out = format_environment_match(em)
    assert "production" in out


def test_format_environment_report_empty():
    out = format_environment_report([])
    assert "No" in out


def test_format_environment_report_non_empty():
    em = attach_environment(_make_match(), env_name="staging")
    out = format_environment_report([em])
    assert "staging" in out


def test_environment_summary_empty():
    assert "0" in environment_summary([])


def test_environment_summary_counts_envs():
    items = [
        attach_environment(_make_match(), env_name="prod"),
        attach_environment(_make_match(), env_name="dev"),
        attach_environment(_make_match(), env_name="prod"),
    ]
    summary = environment_summary(items)
    assert "3" in summary
    assert "2" in summary
