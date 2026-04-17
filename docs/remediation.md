# Remediation

The `hexpose.remediation` module provides actionable guidance for each type of
detected secret, helping teams respond quickly after a scan.

## Getting a hint

```python
from hexpose.remediation import get_hint

hint = get_hint("aws_access_key")
print(hint.summary)
for step in hint.steps:
    print("-", step)
```

`get_hint` accepts a pattern name (matching those defined in `patterns.py`) and
returns a `RemediationHint` dataclass. Unknown patterns fall back to a generic
hint.

## RemediationHint fields

| Field | Type | Description |
|-------|------|-------------|
| `pattern_name` | `str` | Pattern this hint applies to |
| `summary` | `str` | One-line action summary |
| `steps` | `list[str]` | Ordered remediation steps |
| `reference` | `str \| None` | Optional documentation URL |

## Annotating a match

```python
from hexpose.remediation import annotate_match

annotated = annotate_match(match)
print(annotated["remediation"]["steps"])
```

## Formatted report

```python
from hexpose.remediation_report import remediation_summary

print(remediation_summary(scan_result, color=True))
```

The report deduplicates hints — if five AWS keys are found only one hint block
is printed.

## Adding custom hints

Import `_HINTS` and insert a new `RemediationHint`:

```python
from hexpose.remediation import _HINTS, RemediationHint

_HINTS["my_custom_token"] = RemediationHint(
    pattern_name="my_custom_token",
    summary="Revoke the custom token.",
    steps=["Log in to the service and revoke the token."],
)
```
