"""Reporting helpers for match correlation groups."""
from __future__ import annotations

from typing import Dict

from hexpose.match_correlation import CorrelationGroup


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_correlation_group(group: CorrelationGroup) -> str:
    lines = [
        _c(f"[CORRELATED] {group.key}", "1;35"),
        f"  Occurrences : {group.size}",
        f"  Sources     : {', '.join(group.sources) if group.sources else 'n/a'}",
        f"  Patterns    : {', '.join({m.pattern_name for m in group.matches})}",
    ]
    return "\n".join(lines)


def format_correlation_report(
    groups: Dict[str, CorrelationGroup],
    *,
    mode: str = "value",
) -> str:
    if not groups:
        return _c(f"No correlated matches found (mode={mode}).", "2")
    header = _c(f"=== Correlation Report (mode={mode}) ===", "1;35")
    body = "\n\n".join(format_correlation_group(g) for g in groups.values())
    return f"{header}\n\n{body}"


def correlation_summary(groups: Dict[str, CorrelationGroup]) -> str:
    total = sum(g.size for g in groups.values())
    return _c(
        f"{len(groups)} correlation group(s), {total} total match(es) involved.",
        "1",
    )
