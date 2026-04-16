# Trend Analysis

The `hexpose.trend` module provides trend analysis across multiple scan runs by aggregating `Timeline` objects into a `TrendReport`.

## Overview

Each `TrendPoint` represents an aggregated snapshot of a single `Timeline`, capturing:
- **label** — a human-readable identifier (e.g. sprint name, date, version)
- **total_matches** — total number of matches across all events
- **by_severity** — match counts broken down by severity level

## Usage

```python
from hexpose.trend import build_trend_report, format_trend_report
from hexpose.timeline import Timeline

# Build timelines from scan results
t1 = Timeline()
t1.add_event(result_week1)

t2 = Timeline()
t2.add_event(result_week2)

report = build_trend_report([t1, t2], ["week-1", "week-2"])
print(format_trend_report(report))
```

## Output Example

```
Trend Report:
----------------------------------------
  [week-1] total=3  high:2, low:1
  [week-2] total=5  critical:1, high:4
```

## API

### `trend_point_from_timeline(timeline, label) -> TrendPoint`
Aggregate a single `Timeline` into a `TrendPoint`.

### `build_trend_report(timelines, labels) -> TrendReport`
Build a full `TrendReport` from parallel lists of timelines and labels.

### `format_trend_report(report) -> str`
Render the report as a human-readable string.
