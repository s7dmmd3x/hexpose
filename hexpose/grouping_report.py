"""Format grouped matches for display."""
from __future__ import annotations
from typing import Optional
from hexpose.grouping import GroupedMatches

_COLORS = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[94m",
    "low": "\033[96m",
    "reset": "\033[0m",
}


def _colorize(text: str, key: str, use_color: bool) -> str:
    if not use_color:
        return text
    color = _COLORS.get(key.lower(), "")
    return f"{color}{text}{_COLORS['reset']}" if color else text


def format_group_report(
    grouped: GroupedMatches,
    use_color: bool = False,
    max_values: Optional[int] = None,
) -> str:
    lines = [f"Grouped by: {grouped.by}", ""]
    for key in sorted(grouped.keys()):
        matches = grouped.get(key)
        header = _colorize(f"[{key}] ({len(matches)} match(es))", key, use_color)
        lines.append(header)
        shown = matches if max_values is None else matches[:max_values]
        for m in shown:
            lines.append(f"  offset={m.offset:#010x}  pattern={m.pattern_name}  value={m.value!r}")
        if max_values is not None and len(matches) > max_values:
            lines.append(f"  ... and {len(matches) - max_values} more")
        lines.append("")
    return "\n".join(lines)


def group_summary(grouped: GroupedMatches) -> str:
    total = sum(len(v) for v in grouped.groups.values())
    parts = [f"{k}={len(v)}" for k, v in sorted(grouped.groups.items())]
    return f"total={total} | " + ", ".join(parts) if parts else "total=0"
