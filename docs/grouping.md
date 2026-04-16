# Match Grouping

`hexpose.grouping` provides utilities to group scan matches by common dimensions.

## Functions

### `group_by_pattern(matches)`
Groups a list of `Match` objects by their `pattern_name`.

### `group_by_severity(matches)`
Groups matches by severity level (e.g. `critical`, `high`, `medium`, `low`).

### `group_by_offset_range(matches, bucket_size=512)`
Buckets matches into offset ranges of `bucket_size` bytes.

### `group_result(result, by="pattern", **kwargs)`
Convenience wrapper that accepts a `ScanResult` and a dimension string.
Valid values for `by`: `"pattern"`, `"severity"`, `"offset_range"`.

## Example

```python
from hexpose.grouping import group_result

grouped = group_result(scan_result, by="severity")
for severity, matches in grouped.groups.items():
    print(f"{severity}: {len(matches)} match(es)")
```

## `GroupedMatches`

A dataclass holding:
- `by` — the dimension used for grouping
- `groups` — a dict mapping group key → list of `Match`

Call `.as_dict()` for a JSON-serialisable representation.
