# Triage

The `hexpose.triage` module assigns a **risk level** to each match based on a combination of factors:

- Pattern severity (`low`, `medium`, `high`, `critical`)
- Shannon entropy of the matched value
- Presence of the value in a [watchlist](watchlist.md)

## Risk Levels

| Level      | Description                                      |
|------------|--------------------------------------------------|
| `low`      | Low-severity match, low entropy, not watchlisted |
| `medium`   | Medium severity or entropy upgrade from low      |
| `high`     | High severity or entropy upgrade from medium     |
| `critical` | Critical severity or watchlist hit               |

## Usage

```python
from hexpose.triage import triage_match, triage_result
from hexpose.watchlist import Watchlist

wl = Watchlist()
wl.load("watchlist.json")

# Triage a single match
triaged = triage_match(match, watchlist=wl)
print(triaged.risk, triaged.reasons)

# Triage all matches in a ScanResult
triaged_list = triage_result(scan_result, watchlist=wl)
```

## TriagedMatch

```python
@dataclass
class TriagedMatch:
    match: Match       # original match
    risk: str          # one of: low, medium, high, critical
    reasons: list[str] # human-readable explanation
```

## Escalation Rules

1. Base risk is derived from the pattern's severity.
2. If the value has **high Shannon entropy**, risk is upgraded one level.
3. If the value appears in the **watchlist**, risk is escalated to `critical` regardless.
