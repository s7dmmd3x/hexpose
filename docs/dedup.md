# Deduplication

`hexpose` can deduplicate scan matches to reduce noise when the same secret
appears multiple times in a binary or memory dump.

## Strategies

| Strategy | Key | Description |
|---|---|---|
| `value` (default) | `(pattern_name, value)` | Removes matches with the same pattern and secret value, regardless of offset. |
| `exact` | `(pattern_name, offset, value)` | Only removes matches that are identical in every field. |
| `fingerprint` | SHA-256 of `pattern_name:value` | Hash-based deduplication, equivalent to `value` but useful for storage/comparison. |

## Python API

```python
from hexpose.dedup import dedup_result, dedup_matches, DedupStrategy

# Deduplicate a full ScanResult (returns a new ScanResult)
clean = dedup_result(result, strategy=DedupStrategy.VALUE)

# Or deduplicate a raw list of Match objects
clean_matches = dedup_matches(result.matches, strategy=DedupStrategy.EXACT)
```

## CLI usage

Pass `--dedup` (or `--dedup=exact` / `--dedup=fingerprint`) to enable
deduplication during a scan:

```bash
hexpose scan firmware.bin --dedup
hexpose scan firmware.bin --dedup=exact
```

The default strategy when `--dedup` is provided without a value is `value`.

## Notes

- Deduplication is applied **after** filtering and suppression.
- The first occurrence of a duplicate (by file offset) is always kept.
- Original `ScanResult` objects are never mutated; a new object is returned.
