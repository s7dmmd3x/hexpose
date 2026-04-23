"""Tests for hexpose.match_workflow and hexpose.workflow_report."""
from __future__ import annotations

import pytest

from hexpose.scanner import Match
from hexpose.match_workflow import (
    WorkflowMatch,
    open_workflow,
    transition,
    workflow_all,
)
from hexpose.workflow_report import (
    format_workflow_match,
    format_workflow_report,
    workflow_summary,
)


def _make_match(
    pattern_name: str = "aws_access_key",
    value: str = "AKIAIOSFODNN7EXAMPLE",
    severity: str = "high",
    offset: int = 0,
) -> Match:
    return Match(pattern_name=pattern_name, value=value, offset=offset, severity=severity)


# ------------------------------------------------------------------ #
# open_workflow
# ------------------------------------------------------------------ #

def test_open_workflow_returns_workflow_match():
    m = _make_match()
    wm = open_workflow(m)
    assert isinstance(wm, WorkflowMatch)


def test_open_workflow_initial_state_is_open():
    wm = open_workflow(_make_match())
    assert wm.state == "open"


def test_open_workflow_stores_assignee():
    wm = open_workflow(_make_match(), assignee="alice")
    assert wm.assignee == "alice"


def test_open_workflow_no_assignee_is_none():
    wm = open_workflow(_make_match())
    assert wm.assignee is None


def test_open_workflow_has_one_transition():
    wm = open_workflow(_make_match())
    assert len(wm.transitions) == 1


def test_open_workflow_transition_from_is_none():
    wm = open_workflow(_make_match())
    assert wm.transitions[0]["from"] is None


# ------------------------------------------------------------------ #
# transition
# ------------------------------------------------------------------ #

def test_transition_changes_state():
    wm = open_workflow(_make_match())
    wm2 = transition(wm, "in_review")
    assert wm2.state == "in_review"


def test_transition_appends_history():
    wm = open_workflow(_make_match())
    wm2 = transition(wm, "escalated")
    assert len(wm2.transitions) == 2


def test_transition_records_previous_state():
    wm = open_workflow(_make_match())
    wm2 = transition(wm, "resolved")
    assert wm2.transitions[-1]["from"] == "open"


def test_transition_invalid_state_raises():
    wm = open_workflow(_make_match())
    with pytest.raises(ValueError, match="Invalid workflow state"):
        transition(wm, "deleted")


def test_transition_updates_assignee():
    wm = open_workflow(_make_match(), assignee="alice")
    wm2 = transition(wm, "in_review", assignee="bob")
    assert wm2.assignee == "bob"


def test_transition_keeps_assignee_when_not_provided():
    wm = open_workflow(_make_match(), assignee="alice")
    wm2 = transition(wm, "in_review")
    assert wm2.assignee == "alice"


# ------------------------------------------------------------------ #
# as_dict / __str__
# ------------------------------------------------------------------ #

def test_as_dict_contains_required_keys():
    wm = open_workflow(_make_match())
    d = wm.as_dict()
    for key in ("pattern_name", "value", "offset", "severity", "state", "assignee", "transitions"):
        assert key in d


def test_str_contains_state():
    wm = open_workflow(_make_match())
    assert "open" in str(wm)


# ------------------------------------------------------------------ #
# workflow_all
# ------------------------------------------------------------------ #

def test_workflow_all_returns_list():
    matches = [_make_match(), _make_match(pattern_name="github_token")]
    result = workflow_all(matches)
    assert len(result) == 2


def test_workflow_all_all_open():
    matches = [_make_match() for _ in range(3)]
    result = workflow_all(matches)
    assert all(wm.state == "open" for wm in result)


# ------------------------------------------------------------------ #
# report helpers
# ------------------------------------------------------------------ #

def test_format_workflow_match_contains_state():
    wm = open_workflow(_make_match())
    text = format_workflow_match(wm, colour=False)
    assert "open" in text


def test_format_workflow_report_empty():
    assert format_workflow_report([], colour=False) == "No workflow items."


def test_format_workflow_report_lists_items():
    wms = workflow_all([_make_match(), _make_match()])
    text = format_workflow_report(wms, colour=False)
    assert "[1]" in text and "[2]" in text


def test_workflow_summary_counts_states():
    wms = workflow_all([_make_match(), _make_match()])
    summary = workflow_summary(wms)
    assert "open=2" in summary


def test_workflow_summary_empty():
    assert workflow_summary([]) == "workflow: 0 items"
