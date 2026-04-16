# Risk Scoring

`hexpose` computes a numeric risk score (0–100) for every match, combining
severity, entropy, and watchlist signals into a single `grade`.

## How scores are calculated

| Signal | Max contribution |
|--------|------------------|
| Severity base | 80 pts (CRITICAL) |
| Shannon entropy bonus | 15 pts |
| Watchlist hit | 10 pts |

Final score is capped at **100**.

## Grades

| Score range | Grade |
|-------------|-------|
| 90 – 100 | CRITICAL |
| 70 – 89 | HIGH |
| 50 – 69 | MEDIUM |
| 30 – 49 | LOW |
| 0 – 29 | INFO |

## API

```python
from hexpose.scoring import score_match, score_result
from hexpose.score_report import format_score_report, score_summary

# Score a single match
scored = score_match(match, watchlisted=False)
print(scored.grade, scored.final_score)

# Score all matches in a result
scored_list = score_result(result, watchlist=wl)

# Pretty-print
print(format_score_report(scored_list))

# Distribution
print(score_summary(scored_list))
```

## ScoredMatch fields

- `match` — original `Match` object
- `base_score` — severity contribution
- `entropy_bonus` — entropy contribution
- `watchlist_bonus` — watchlist contribution
- `final_score` — capped total
- `grade` — human-readable risk grade
