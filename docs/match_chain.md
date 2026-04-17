# Match Chain

The `match_chain` module provides a lightweight **pipeline** for transforming or
filtering `Match` objects before they reach the reporter or exporter.

## Concepts

- **`MatchChain`** — an ordered list of *transform* callables.
- **Transform** — any `Callable[[Match], Match | None]`.  Returning `None` drops
  the match from the pipeline.
- **`build_chain(*fns)`** — convenience factory.

## Quick start

```python
from hexpose.match_chain import build_chain
from hexpose.chain_builtins import drop_low_entropy, require_min_length

chain = build_chain(
    drop_low_entropy(min_entropy=3.5),
    require_min_length(12),
)

filtered = chain.run_all(scanner_result.matches)
```

## Built-in steps (`chain_builtins`)

| Factory / function | Description |
|--------------------|-------------|
| `drop_low_entropy(min_entropy)` | Drops matches whose value Shannon entropy is below the threshold |
| `drop_patterns(names)` | Drops matches whose `pattern_name` is in the provided set |
| `require_min_length(min_len)` | Drops matches shorter than `min_len` characters |
| `uppercase_value` | Mutates `value` to upper-case (example mutator) |

## Writing custom steps

```python
def my_step(match):
    if "test" in match.value.lower():
        return None   # drop test credentials
    return match

chain = build_chain(my_step)
```

Steps are composable — add as many as needed via `chain.add(fn)` or pass them
all to `build_chain`.
