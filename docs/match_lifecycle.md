# Match Lifecycle

The `match_lifecycle` module tracks the lifecycle state of each detected match
across scan runs: **open**, **updated**, and **resolved**.

## Data Model

```python
@dataclass
class LifecycleMatch:
    match: Match
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    state: str  # "open" | "updated" | "resolved"
```

## Functions

### `open_match(match, *, now=None) -> LifecycleMatch`
Wrap a new `Match` as an open lifecycle entry.

### `resolve_match(lm, *, now=None) -> LifecycleMatch`
Mark an existing lifecycle entry as resolved.

### `update_match(lm, new_match, *, now=None) -> LifecycleMatch`
Replace the underlying match while preserving `created_at`.

### `lifecycle_all(matches, *, now=None) -> list[LifecycleMatch]`
Open lifecycle entries for a list of matches in bulk.

## Example

```python
from hexpose.match_lifecycle import open_match, resolve_match

lm = open_match(match)
print(lm.state)          # "open"

resolved = resolve_match(lm)
print(resolved.state)    # "resolved"
print(resolved.as_dict())
```

## Reporting

```python
from hexpose.lifecycle_report import format_lifecycle_report, lifecycle_summary

print(format_lifecycle_report(items))
print(lifecycle_summary(items))
```
