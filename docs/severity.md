# Severity Levels

Hexpose assigns every finding a **severity level** that indicates how sensitive
or dangerous the detected secret is likely to be.

## Levels

| Level      | Integer | Meaning |
|------------|---------|------------------------------------------------------------|
| `low`      | 1       | Informational; unlikely to cause immediate harm            |
| `medium`   | 2       | Moderate risk; should be reviewed                          |
| `high`     | 3       | Sensitive credential; rotate as soon as possible           |
| `critical` | 4       | Highly sensitive (e.g. private keys, root tokens); act now |

Levels are ordered so that `low < medium < high < critical`.

## Python API

```python
from hexpose.severity import Severity, parse_severity, severity_at_least

# Parse from string (case-insensitive)
level = parse_severity("high")          # Severity.HIGH
level = Severity.from_string("CRITICAL") # Severity.CRITICAL

# Compare
print(level.label())                    # "critical"
print(level >= Severity.HIGH)           # True

# Filter helper used internally by FilterConfig
if severity_at_least(level, minimum=Severity.MEDIUM):
    print("finding passes the minimum severity threshold")
```

## CLI flag

Pass `--min-severity` to discard findings below a given level:

```bash
hexpose scan firmware.bin --min-severity high
```

Only `high` and `critical` findings will appear in the output.

## Pattern definitions

Each pattern in `patterns.py` (and any loaded plugin) declares its severity
using the same lowercase string values:

```python
SecretPattern(
    name="aws_access_key",
    pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    severity="critical",
)
```

The scanner converts the string to a `Severity` enum value when building a
`Match` object, enabling consistent ordering and filtering throughout the
pipeline.
