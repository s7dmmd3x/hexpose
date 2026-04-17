# Match Labels

`hexpose.match_labels` lets you attach free-form string labels to any `Match`
object and then filter or summarise by those labels.

## Quick start

```python
from hexpose.match_labels import label_match, matches_with_label, label_summary

lm = label_match(match, "cloud", "pii")
print(lm.has("cloud"))   # True
print(lm.as_dict())
```

## API

### `label_match(match, *labels) -> LabeledMatch`

Wrap a `Match` and optionally seed it with one or more labels.

### `LabeledMatch`

| Method | Description |
|--------|-------------|
| `add(label)` | Attach a label (whitespace stripped, duplicates ignored). |
| `has(label)` | Return `True` if the label is present. |
| `as_dict()` | Serialise to a plain dictionary. |

### `matches_with_label(labeled, label) -> List[LabeledMatch]`

Filter a list of `LabeledMatch` objects, keeping only those that carry
`label`.

### `label_summary(labeled) -> dict`

Return a `{label: count}` mapping across all labeled matches.

## Report helpers

```python
from hexpose.labels_report import format_labels_report, labels_summary_text

print(format_labels_report(labeled_matches))
print(labels_summary_text(labeled_matches))
```
