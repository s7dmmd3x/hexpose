# Watchlist

The **watchlist** feature lets you maintain a curated set of known-bad secret
values. Any scan match whose extracted value appears in the watchlist is
automatically flagged, regardless of entropy score or severity filter.

## File format

A watchlist is a plain JSON array of strings:

```json
[
  "AKIAIOSFODNN7EXAMPLE",
  "my-hardcoded-db-password"
]
```

## Programmatic usage

```python
from hexpose.watchlist import Watchlist
from hexpose.watchlist_annotator import annotate_result, watchlisted_matches

# Load (returns empty watchlist if file is missing)
wl = Watchlist.load(".hexpose_watchlist.json")

# Annotate every match in a ScanResult
result = scanner.scan_file("firmware.bin")
annotate_result(result, wl)

# Inspect the flag
for match in result.matches:
    if match.metadata.get("watchlisted"):
        print(f"[WATCHLISTED] {match.pattern_name}: {match.value}")

# Or get only watchlisted matches directly
bad = watchlisted_matches(result, wl)
```

## Managing the watchlist

```python
wl = Watchlist.load(".hexpose_watchlist.json")
wl.add("newly_leaked_token")
wl.remove("rotated_old_token")
wl.save(".hexpose_watchlist.json")
```

## Notes

- Comparison is **exact string match** (case-sensitive).
- The watchlist is independent of pattern severity — a watchlisted value is
  always surfaced even if it would normally be filtered out.
- Combine with `hexpose.filter.filter_matches` for fine-grained control over
  which findings are reported.
