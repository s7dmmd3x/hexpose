"""match_workflow.py – attach a workflow state and transition history to a match."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from hexpose.scanner import Match

_VALID_STATES = {"open", "in_review", "escalated", "resolved", "wont_fix"}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class WorkflowMatch:
    """A Match decorated with workflow state and transition log."""

    match: Match
    state: str
    assignee: Optional[str]
    transitions: List[dict] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "state": self.state,
            "assignee": self.assignee,
            "transitions": list(self.transitions),
        }

    def __str__(self) -> str:
        assignee_part = f" [{self.assignee}]" if self.assignee else ""
        return (
            f"{self.match.pattern_name} | state={self.state}{assignee_part}"
        )


def open_workflow(
    match: Match,
    *,
    assignee: Optional[str] = None,
) -> WorkflowMatch:
    """Create a new WorkflowMatch in the *open* state."""
    ts = _utcnow()
    transition = {"from": None, "to": "open", "at": ts, "assignee": assignee}
    return WorkflowMatch(
        match=match,
        state="open",
        assignee=assignee,
        transitions=[transition],
    )


def transition(
    wm: WorkflowMatch,
    new_state: str,
    *,
    assignee: Optional[str] = None,
) -> WorkflowMatch:
    """Transition *wm* to *new_state*, recording the change."""
    if new_state not in _VALID_STATES:
        raise ValueError(
            f"Invalid workflow state {new_state!r}. "
            f"Valid states: {sorted(_VALID_STATES)}"
        )
    ts = _utcnow()
    new_transitions = list(wm.transitions) + [
        {"from": wm.state, "to": new_state, "at": ts, "assignee": assignee}
    ]
    return WorkflowMatch(
        match=wm.match,
        state=new_state,
        assignee=assignee if assignee is not None else wm.assignee,
        transitions=new_transitions,
    )


def workflow_all(
    matches: List[Match],
    *,
    assignee: Optional[str] = None,
) -> List[WorkflowMatch]:
    """Bulk-open workflow records for a list of matches."""
    return [open_workflow(m, assignee=assignee) for m in matches]
