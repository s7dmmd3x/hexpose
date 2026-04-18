# match_mask

The `match_mask` module provides safe, display-ready masking of sensitive match values.

## Overview

After scanning, raw secret values are stored in `Match` objects. Before logging,
displaying, or exporting results it is good practice to obscure those values.
`match_mask` wraps each `Match` in a `MaskedMatch` that replaces the raw value
with a redacted form.

## MaskedMatch

```python
@dataclass
class MaskedMatch:
    match: Match
    masked_value: str
    mask_mode: str       # 'full' | 'partial'
    reveal_chars: int
```

## mask_match

```python
from hexpose.match_mask import mask_match

mm = mask_match(match, mode="partial", reveal_chars=4)
print(mm)  # [aws_access_key] AKIA**** (mode=partial)
```

| mode      | behaviour                              |
|-----------|----------------------------------------|
| `partial` | keeps first *reveal_chars*, masks rest |
| `full`    | replaces entire value with `[REDACTED]`|

## mask_all

```python
from hexpose.match_mask import mask_all

masked = mask_all(result.matches, mode="full")
```

## mask_report

Human-readable formatting:

```python
from hexpose.mask_report import format_mask_report, mask_summary

print(format_mask_report(masked))
print(mask_summary(masked))
```
