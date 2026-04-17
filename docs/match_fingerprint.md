# Match Fingerprinting

`hexpose.match_fingerprint` assigns a stable SHA-256 fingerprint to every
`Match` object.  Fingerprints are used for deduplication, baseline diffing,
and suppression lists.

## Core API

```python
from hexpose.match_fingerprint import fingerprint_match, fingerprint_result, unique_fingerprints

# Single match
fm = fingerprint_match(match)          # FingerprintedMatch
print(fm.fingerprint)                  # 64-char hex string

# All matches in a ScanResult
fms = fingerprint_result(result)

# Deduplicated fingerprint list
fps = unique_fingerprints(result)
```

## Stability

By default the fingerprint is computed from `pattern_name` and `value` only,
so the same secret found at a different offset produces the **same** fingerprint
across re-scans.  Pass `include_offset=True` to make fingerprints
occurrence-specific.

```python
fm = fingerprint_match(match, include_offset=True)
```

## Reporting

```python
from hexpose.fingerprint_report import format_fingerprint_report, fingerprint_summary

print(format_fingerprint_report(fms))
print(fingerprint_summary(fms))
```

Example output:

```
[3f9a1c02b4e1] aws_key @ offset 128: AKIAIOSFODNN7EXAMPLE
Fingerprinted matches: 3 total, 2 unique
```
