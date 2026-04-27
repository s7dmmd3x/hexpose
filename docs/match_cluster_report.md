# Match Cluster Report

The `match_cluster_report` module provides human-readable formatting for
`MatchCluster` objects produced by `hexpose.match_cluster`.

## Functions

### `format_cluster(cluster, *, colour=True) -> str`

Renders a single `MatchCluster` as a multi-line block showing the pattern
name, total match count, and a preview of each matched value.

```python
from hexpose.match_cluster import cluster_by_pattern
from hexpose.match_cluster_report import format_cluster

clusters = cluster_by_pattern(matches)
for c in clusters:
    print(format_cluster(c))
```

Long values (> 60 characters) are automatically truncated with `...`.

---

### `format_cluster_report(clusters, *, colour=True) -> str`

Renders a full report for a list of clusters, separating each cluster block
with a horizontal divider.  Returns a *"No clusters found."* message when
the list is empty.

```python
from hexpose.match_cluster_report import format_cluster_report

print(format_cluster_report(clusters, colour=False))
```

---

### `cluster_summary(clusters) -> str`

Returns a compact one-line summary suitable for dashboards or CI output:

```
Clusters: 3 | Total matches: 12 | Patterns: aws_access_key, github_token, jwt
```

```python
from hexpose.match_cluster_report import cluster_summary

print(cluster_summary(clusters))
```

## Colour support

All formatting functions accept a `colour` keyword argument (default `True`).
Pass `colour=False` when writing to files or non-TTY streams.
