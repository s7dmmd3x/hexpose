"""audit_report.py — formatting helpers for AuditedMatch results."""
from __future__ import annotations

from typing import List

from hexpose.match_audit import AuditedMatch


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_audit_event_line(action: str, actor: str, timestamp: str, notes: str) -> str:
    parts = [
        _c(action, "36"),
        f"by {_c(actor, '33')}",
        f"at {timestamp}",
    ]
    if notes:
        parts.append(f"— {notes}")
    return "  " + "  ".join(parts)


def format_audited_match(am: AuditedMatch) -> str:
    header = (
        f"{_c(am.match.pattern_name, '1;35')}  "
        f"severity={_c(am.match.severity, '33')}  "
        f"offset={am.match.offset}"
    )
    lines = [header]
    if am.events:
        lines.append(_c("  Audit trail:", "2"))
        for ev in am.events:
            lines.append(format_audit_event_line(ev.action, ev.actor, ev.timestamp.isoformat(), ev.notes))
    else:
        lines.append(_c("  No audit events recorded.", "2"))
    return "\n".join(lines)


def format_audit_report(audited: List[AuditedMatch]) -> str:
    if not audited:
        return _c("No audited matches.", "2")
    blocks = [format_audited_match(am) for am in audited]
    return "\n\n".join(blocks)


def audit_summary(audited: List[AuditedMatch]) -> str:
    total = len(audited)
    total_events = sum(len(am.events) for am in audited)
    actors = {ev.actor for am in audited for ev in am.events}
    return (
        f"{_c(str(total), '1')} audited match(es), "
        f"{_c(str(total_events), '1')} event(s), "
        f"actors: {', '.join(sorted(actors)) or 'none'}"
    )
