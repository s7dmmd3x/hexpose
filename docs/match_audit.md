# Match Audit Trail

The `match_audit` module provides a lightweight audit trail for `Match` objects,
recording who performed what action and when.

## Core types

### `AuditEvent`

A single audit record.

| Field | Type | Description |
|-------|------|-------------|
| `action` | `str` | What was done (e.g. `"created"`, `"reviewed"`) |
| `actor` | `str` | Who performed the action |
| `timestamp` | `datetime` | UTC time of the event |
| `notes` | `str` | Optional free-text notes |

### `AuditedMatch`

Wraps a `Match` with an ordered list of `AuditEvent` records.

```python
from hexpose.match_audit import audit_match

am = audit_match(match, action="imported", actor="pipeline")
am.add(action="reviewed", actor="alice", notes="confirmed real key")
am.add(action="closed", actor="alice")

print(am.last_event().action)   # "closed"
print(am.has_action("reviewed"))  # True
```

## Functions

### `audit_match(match, action, actor, notes="") -> AuditedMatch`

Wrap a single match and record the first event.

### `audit_all(matches, action, actor, notes="") -> List[AuditedMatch]`

Convenience wrapper that calls `audit_match` for every match in a list.

## Reporting

```python
from hexpose.audit_report import format_audit_report, audit_summary

print(format_audit_report(audited_matches))
print(audit_summary(audited_matches))
```

## Serialisation

Both `AuditedMatch` and `AuditEvent` expose an `as_dict()` method suitable for
JSON export.

```python
import json
print(json.dumps(am.as_dict(), default=str, indent=2))
```
