# Match Narrative

The `match_narrative` module attaches human-readable narrative summaries and
actionable recommendations to individual `Match` objects.

## Overview

When presenting scan results to non-security audiences it is useful to explain
*why* a finding matters and *what* should be done about it.  `NarrativeMatch`
wraps a `Match` with a plain-English description and a list of remediation
recommendations derived from the pattern name and severity.

## API

### `attach_narrative(match, narrative=None) -> NarrativeMatch`

Return a `NarrativeMatch` for *match*.  If *narrative* is provided it overrides
the automatically generated text.

```python
from hexpose.match_narrative import attach_narrative

nm = attach_narrative(match)
print(nm.narrative)
for rec in nm.recommendations:
    print(" •", rec)
```

### `attach_narrative_all(matches) -> List[NarrativeMatch]`

Convenience wrapper that calls `attach_narrative` for every item in *matches*.

```python
from hexpose.match_narrative import attach_narrative_all

narrated = attach_narrative_all(scan_result.matches)
```

## NarrativeMatch

| Attribute | Type | Description |
|---|---|---|
| `match` | `Match` | The original match object |
| `narrative` | `str` | Human-readable explanation of the risk |
| `recommendations` | `List[str]` | Ordered list of remediation steps |

`NarrativeMatch.as_dict()` returns a JSON-serialisable dictionary containing
all fields including the nested match attributes.

## Reporting

Use `hexpose.narrative_report` to render `NarrativeMatch` objects for terminal
output:

```python
from hexpose.narrative_report import format_narrative_report, narrative_summary

print(format_narrative_report(narrated))
print(narrative_summary(narrated))
```

## Built-in Narratives

Narratives are selected by matching substrings of the pattern name against an
internal template dictionary.  Patterns currently covered include:

- `aws_access_key`
- `aws_secret_key`
- `github_token`
- `jwt`
- `password`
- `generic_secret`

Unrecognised patterns fall back to a generic narrative that recommends manual
review.
