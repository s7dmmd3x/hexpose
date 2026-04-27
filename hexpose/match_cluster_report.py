"""Reporting utilities for match clusters."""

from __future__ import annotations

from typing import List

from hexpose.match_cluster import MatchCluster


def _c(code: str, text: str) -> str:
    """Wrap text in an ANSI colour code."""
    return f"\033[{code}m{text}\033[0m"


def format_cluster(cluster: MatchCluster, *, colour: bool = True) -> str:
    """Return a human-readable block for a single cluster."""
    header = f"Pattern : {cluster.pattern_name}"
    size_line = f"Matches : {cluster.size()}"
    if colour:
        header = _c("1;36", header)
        size_line = _c("0;33", size_line)

    lines = [header, size_line]
    for match in cluster.matches:
        value_preview = (match.value[:60] + "...") if len(match.value) > 60 else match.value
        severity = getattr(match, "severity", "unknown")
        entry = f"  [{severity}] offset={match.offset}  {value_preview}"
        if colour:
            entry = _c("0;37", entry)
        lines.append(entry)
    return "\n".join(lines)


def format_cluster_report(
    clusters: List[MatchCluster], *, colour: bool = True
) -> str:
    """Return a full report for a list of clusters."""
    if not clusters:
        msg = "No clusters found."
        return _c("0;90", msg) if colour else msg

    sections = [format_cluster(c, colour=colour) for c in clusters]
    divider = _c("0;90", "-" * 60) if colour else "-" * 60
    return ("\n" + divider + "\n").join(sections)


def cluster_summary(clusters: List[MatchCluster]) -> str:
    """Return a one-line summary of cluster statistics."""
    total_clusters = len(clusters)
    total_matches = sum(c.size() for c in clusters)
    pattern_names = sorted({c.pattern_name for c in clusters})
    patterns_str = ", ".join(pattern_names) if pattern_names else "none"
    return (
        f"Clusters: {total_clusters} | "
        f"Total matches: {total_matches} | "
        f"Patterns: {patterns_str}"
    )
