# Match Lineage

The `match_lineage` module tracks which processing steps each `Match` has
passed through, giving you a full audit trail from raw detection to final
output.

## Data Model

```python
@dataclass
class LineageMatch:
    match: Match
    steps: List[str]
```

`steps` is an ordered list of named processing stages (e.g. `"filter"`,
`"redact"`, `"score"`).

## Usage

```python
from hexpose.match_lineage import track_lineage, track_lineage_all

# Wrap a single match
lm = track_lineage(match, "filter", "redact")
lm.add("score")          # chain more steps later
print(lm.has_step("score"))  # True

# Wrap all matches in a ScanResult
lineage_matches = track_lineage_all(result, "filter")
```

## Report

```python
from hexpose.lineage_report import format_lineage_report, lineage_summary

print(format_lineage_report(lineage_matches))
print(lineage_summary(lineage_matches))
```

Example output:

```
=== Lineage Report ===
[high] aws_key  lineage: filter -> redact -> score
[medium] github_token  lineage: filter

2 match(es) tracked across 3 unique step(s): filter, redact, score
```

## Serialisation

`LineageMatch.as_dict()` returns a plain dictionary suitable for JSON export:

```python
{
  "pattern_name": "aws_key",
  "offset": 0,
  "value": "AKIA...",
  "severity": "high",
  "steps": ["filter", "redact", "score"]
}
```
