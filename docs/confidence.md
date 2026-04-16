# Confidence Scoring

`hexpose.confidence` assigns a confidence score (0.0–1.0) to each match based on
multiple heuristic factors.

## Factors

| Factor | Max contribution |
|---|---|
| Severity (critical → info) | 0.40 |
| Shannon entropy of value | 0.35 |
| Value length (≥20 / ≥8) | 0.15 |

Scores are capped at `1.0`.

## Levels

| Score range | Level |
|---|---|
| 0.75 – 1.0 | `high` |
| 0.45 – 0.74 | `medium` |
| 0.0 – 0.44 | `low` |

## Usage

```python
from hexpose.confidence import score_confidence, score_confidence_all
from hexpose.confidence_report import format_confidence_report, confidence_summary

results = score_confidence_all(scan_result.matches)
print(format_confidence_report(results))
print(confidence_summary(results))
```

## Example output

```
[HIGH] aws_key score=0.90 offset=128 reasons=[severity=critical, high entropy (4.32), long value (>=20 chars)]
[LOW]  generic_token score=0.25 offset=512 reasons=[severity=low, moderate length (>=8 chars)]
```

## API

### `score_confidence(match) -> ConfidenceResult`

Score a single match.

### `score_confidence_all(matches) -> list[ConfidenceResult]`

Score a list of matches.

### `ConfidenceResult.as_dict() -> dict`

Serialise to a plain dictionary suitable for JSON export.
