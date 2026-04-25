# Match Escalation

The `match_escalation` module detects whether a finding has **escalated** compared
to a known baseline — either because its severity increased or because it appears
more frequently than before.

## Core types

### `EscalatedMatch`

| Field | Type | Description |
|---|---|---|
| `match` | `Match` | The underlying match |
| `previous_severity` | `str \| None` | Severity recorded in the baseline (`None` = new finding) |
| `current_severity` | `str` | Severity of the current scan |
| `escalated` | `bool` | `True` when escalation criteria are met |
| `reason` | `str` | Human-readable reason string |
| `previous_count` | `int` | How many times this pattern appeared previously |
| `current_count` | `int` | How many times it appears now |

## Functions

### `escalate_match(match, baseline_severity, previous_count, current_count)`

Evaluates a single `Match` and returns an `EscalatedMatch`.

```python
from hexpose.match_escalation import escalate_match

em = escalate_match(match, baseline_severity="low", previous_count=1, current_count=3)
if em.escalated:
    print(f"Escalation detected: {em.reason}")
```

### `escalate_result(result, baseline)`

Applies `escalate_match` to every match in a `ScanResult`.

```python
from hexpose.match_escalation import escalate_result

baseline = {
    "aws_access_key": {"severity": "medium", "count": 2},
}
escalated = escalate_result(scan_result, baseline=baseline)
```

## Reporting

```python
from hexpose.escalation_report import format_escalation_report, escalation_summary

print(format_escalation_report(escalated, only_escalated=True))
print(escalation_summary(escalated))
```

## Escalation criteria

1. **New finding** — the pattern was not present in the baseline.
2. **Severity increase** — the current severity rank is higher than the baseline.
3. **Count increase** — the pattern appears more times than before.

Multiple criteria can apply simultaneously; the `reason` field lists all of them
separated by `"; "`.
