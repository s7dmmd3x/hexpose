"""Tests for hexpose.match_classification and hexpose.classification_report."""
import pytest
from hexpose.scanner import Match
from hexpose.match_classification import (
    classify_match,
    classify_all,
    ClassifiedMatch,
)
from hexpose.classification_report import (
    format_classified_match,
    format_classification_report,
    classification_summary,
)


def _make_match(pattern_name="test_pattern", severity="high", value="secret123", offset=0):
    return Match(
        pattern_name=pattern_name,
        value=value,
        offset=offset,
        severity=severity,
        line=1,
    )


def test_classify_match_returns_classified_match():
    m = _make_match(pattern_name="aws_access_key")
    cm = classify_match(m)
    assert isinstance(cm, ClassifiedMatch)


def test_classify_aws_key_gives_cloud_credential():
    m = _make_match(pattern_name="aws_access_key", severity="critical")
    cm = classify_match(m)
    assert cm.category == "cloud_credential"


def test_classify_github_token_gives_version_control():
    m = _make_match(pattern_name="github_token")
    cm = classify_match(m)
    assert cm.category == "version_control"


def test_classify_jwt_gives_auth_token():
    m = _make_match(pattern_name="jwt_secret")
    cm = classify_match(m)
    assert cm.category == "auth_token"


def test_classify_unknown_pattern_gives_generic():
    m = _make_match(pattern_name="random_pattern_xyz")
    cm = classify_match(m)
    assert cm.category == "generic"


def test_tier_definite_for_high_severity_known_category():
    m = _make_match(pattern_name="aws_access_key", severity="critical")
    cm = classify_match(m)
    assert cm.tier == "definite"


def test_tier_probable_for_known_category_low_severity():
    m = _make_match(pattern_name="github_token", severity="low")
    cm = classify_match(m)
    assert cm.tier == "probable"


def test_tier_possible_for_generic_low_severity():
    m = _make_match(pattern_name="random_xyz", severity="low")
    cm = classify_match(m)
    assert cm.tier == "possible"


def test_keywords_matched_populated():
    m = _make_match(pattern_name="aws_access_key")
    cm = classify_match(m)
    assert "aws" in cm.keywords_matched


def test_classify_all_returns_list():
    matches = [_make_match(pattern_name="aws_key"), _make_match(pattern_name="jwt_token")]
    result = classify_all(matches)
    assert len(result) == 2
    assert all(isinstance(r, ClassifiedMatch) for r in result)


def test_classify_all_empty():
    assert classify_all([]) == []


def test_as_dict_contains_required_keys():
    m = _make_match(pattern_name="aws_access_key", severity="high")
    cm = classify_match(m)
    d = cm.as_dict()
    for key in ("pattern_name", "category", "tier", "keywords_matched", "severity", "offset"):
        assert key in d


def test_format_classified_match_contains_category():
    m = _make_match(pattern_name="aws_access_key")
    cm = classify_match(m)
    text = format_classified_match(cm, colour=False)
    assert "cloud_credential" in text


def test_format_classified_match_contains_tier():
    m = _make_match(pattern_name="aws_access_key", severity="critical")
    cm = classify_match(m)
    text = format_classified_match(cm, colour=False)
    assert "definite" in text.lower()


def test_format_classification_report_empty():
    assert format_classification_report([], colour=False) == "No classified matches."


def test_format_classification_report_non_empty():
    matches = [_make_match(pattern_name="github_token")]
    classified = classify_all(matches)
    report = format_classification_report(classified, colour=False)
    assert "github_token" in report


def test_classification_summary_empty():
    assert "none" in classification_summary([])


def test_classification_summary_counts():
    matches = [_make_match(pattern_name="aws_key"), _make_match(pattern_name="aws_secret")]
    classified = classify_all(matches)
    summary = classification_summary(classified)
    assert "2" in summary
