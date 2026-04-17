"""Formatting helpers for labeled match reports."""
from __future__ import annotations
from typing import List
from hexpose.match_labels import LabeledMatch, label_summary

_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "cyan": "\033[36m",
    "yellow": "\033[33m",
}


def _c(key: str, text: str, color: bool = True) -> str:
    if not color:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['reset']}"


def format_labeled_match(lm: LabeledMatch, color: bool = True) -> str:
    labels_str = ", ".join(lm.labels) if lm.labels else "(none)"
    name = _c("cyan", lm.match.pattern_name, color)
    labels_fmt = _c("yellow", labels_str, color)
    return f"{name}  labels=[{labels_fmt}]  value={lm.match.value!r}"


def format_labels_report(labeled: List[LabeledMatch], color: bool = True) -> str:
    if not labeled:
        return "No labeled matches."
    lines = [_c("bold", "Labeled Matches", color), ""]
    for lm in labeled:
        lines.append(format_labeled_match(lm, color=color))
    return "\n".join(lines)


def labels_summary_text(labeled: List[LabeledMatch], color: bool = True) -> str:
    summary = label_summary(labeled)
    if not summary:
        return "No labels applied."
    lines = [_c("bold", "Label Summary", color)]
    for lbl, count in sorted(summary.items()):
        lines.append(f"  {_c('cyan', lbl, color)}: {count}")
    return "\n".join(lines)
