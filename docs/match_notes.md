# Match Notes

The `match_notes` module lets analysts attach free-text notes to individual
`Match` objects found during a scan.

## Usage

```python
from hexpose.match_notes import note_match, annotate_result

# Attach notes directly
nm = note_match(match, "Rotate this key", "Found in prod binary")
print(nm.notes)        # ['Rotate this key', 'Found in prod binary']
print(nm.has_notes())  # True

# Bulk annotation by pattern name
notes_map = {
    "aws_key": ["Check IAM permissions"],
    "github_token": ["Revoke via GitHub settings"],
}
noted = annotate_result(scan_result.matches, notes_map)
```

## Reporting

```python
from hexpose.notes_report import format_notes_report, notes_summary

print(format_notes_report(noted))
print(notes_summary(noted))
```

## API

### `NotedMatch`
| Attribute | Type | Description |
|-----------|------|-------------|
| `match`   | `Match` | Original match |
| `notes`   | `list[str]` | Analyst notes |

### `note_match(match, *notes) -> NotedMatch`
Create a `NotedMatch` with optional initial notes.

### `annotate_result(matches, notes_map) -> list[NotedMatch]`
Bulk-annotate a list of matches using a `{pattern_name: [notes]}` mapping.
