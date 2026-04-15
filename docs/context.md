# Context Extraction

`hexpose.context` provides utilities to retrieve the surrounding lines of text
around a secret match, making findings easier to understand in reports.

## API

### `extract_context(data, offset, match_length, context_lines=2) -> MatchContext`

Given the raw bytes of a scanned buffer and the byte offset of a match, returns
a `MatchContext` object containing:

| Field          | Type        | Description                                  |
|----------------|-------------|----------------------------------------------|
| `before_lines` | `List[str]` | Lines immediately before the matching line   |
| `match_line`   | `str`       | The line that contains the matched secret    |
| `after_lines`  | `List[str]` | Lines immediately after the matching line    |
| `line_number`  | `int`       | 1-based line number of the match             |

**Parameters**

- `data` — raw `bytes` of the file or memory dump being scanned.
- `offset` — byte offset returned by the regex match (`match.start()`).
- `match_length` — length of the matched string in bytes.
- `context_lines` — how many lines before/after to include (default `2`).

### `MatchContext.as_text(mark=True) -> str`

Renders the context block as a human-readable string.  
When `mark=True` the matching line is prefixed with `> `; surrounding lines use
two-space indentation.

## Example

```python
from hexpose.context import extract_context

with open("firmware.bin", "rb") as fh:
    data = fh.read()

# Assume `match` is a re.Match object from a pattern scan
ctx = extract_context(data, match.start(), len(match.group()), context_lines=3)
print(ctx.as_text())
```

Output:

```
  [wifi]
  ssid = MyNetwork
> password = hunter2
  timeout = 30
```

## Integration with Scanner

The `Scanner` can be extended to attach a `MatchContext` to each `Match` object
by calling `extract_context` after every regex hit, enabling richer CLI output
and SARIF reports.
