# Match CVE Association

The `match_cve` module links scan matches to known CVE identifiers, helping
prioritise remediation based on publicly disclosed vulnerabilities.

## Overview

When a secret is found in a binary or memory dump, knowing whether that secret
type has a related CVE provides additional context for risk assessment.

## API

### `attach_cve(match, *, extra_cves=None, reference_url=None) -> CVEMatch`

Attaches CVE information to a single `Match`.

```python
from hexpose.match_cve import attach_cve

cve_match = attach_cve(match, reference_url="https://nvd.nist.gov")
print(cve_match)  # [aws_access_key] CVEs: CVE-2020-15228
```

### `attach_cve_all(result, *, extra_cves=None, reference_url=None) -> List[CVEMatch]`

Attaches CVE information to every match in a `ScanResult`.

```python
from hexpose.match_cve import attach_cve_all

cve_matches = attach_cve_all(scan_result)
```

## `CVEMatch` dataclass

| Field | Type | Description |
|---|---|---|
| `match` | `Match` | Original match |
| `cves` | `List[str]` | Associated CVE IDs |
| `reference_url` | `Optional[str]` | Optional NVD / advisory URL |

## Reporting

```python
from hexpose.cve_report import format_cve_report, cve_summary

print(format_cve_report(cve_matches))
print(cve_summary(cve_matches))
```

## Extending the CVE map

The built-in `_PATTERN_CVE_MAP` in `match_cve.py` maps pattern-name keywords
to CVE lists.  Pass `extra_cves` to `attach_cve` / `attach_cve_all` to supply
additional identifiers at call-time without modifying the module.
