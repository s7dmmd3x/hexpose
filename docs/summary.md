# Scan Summary

The `hexpose.summary` module provides aggregated statistics over one or more `ScanResult` objects.

## Usage

```python
from hexpose.summary import summarize, format_summary

results = scanner.scan_files(["firmware.bin", "dump.raw"])
summary = summarize(results)
print(format_summary(summary))
```

## Output example

```
Files scanned  : 2
Files with hits: 1
Total matches  : 4
Unique values  : 3
By severity    : high=3, low=1
By pattern     : aws_key=2, github_token=2
```

## API

### `summarize(results: List[ScanResult]) -> ScanSummary`

Accepts a list of `ScanResult` objects and returns a `ScanSummary` dataclass.

### `ScanSummary`

| Field | Type | Description |
|---|---|---|
| `total_matches` | int | Total number of matches across all results |
| `by_severity` | dict | Match counts keyed by severity string |
| `by_pattern` | dict | Match counts keyed by pattern name |
| `unique_values` | int | Number of distinct matched secret values |
| `files_scanned` | int | Total files/sources scanned |
| `files_with_findings` | int | Sources that had at least one match |

### `format_summary(summary: ScanSummary) -> str`

Returns a human-readable multi-line string suitable for CLI output.

### `ScanSummary.as_dict() -> dict`

Serializes the summary to a plain dictionary for JSON export.
