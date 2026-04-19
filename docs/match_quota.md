# Match Quota

The `match_quota` module lets you cap the number of findings returned by a scan — either globally or per pattern — to keep reports manageable.

## QuotaConfig

```python
from hexpose.match_quota import QuotaConfig

config = QuotaConfig(
    max_total=100,          # hard cap across all patterns
    max_per_pattern=10,     # default per-pattern cap
    per_pattern_overrides={ # override for specific patterns
        "aws_key": 3,
    },
)
```

## Applying a quota

```python
from hexpose.match_quota import apply_quota, apply_quota_to_result

# From a plain list of Match objects
quota_result = apply_quota(matches, config)

# From a ScanResult
quota_result = apply_quota_to_result(scan_result, config)

print(quota_result.dropped)  # number of matches removed
print(quota_result.capped)   # True if max_total was hit
```

## QuotaResult

| Field | Type | Description |
|-------|------|-------------|
| `matches` | `List[Match]` | Surviving matches after quota |
| `dropped` | `int` | Number of matches removed |
| `capped` | `bool` | Whether the total cap was reached |

## Reporting

```python
from hexpose.quota_report import format_quota_result, quota_summary

print(format_quota_result(quota_result))
print(quota_summary(quota_result))
```
