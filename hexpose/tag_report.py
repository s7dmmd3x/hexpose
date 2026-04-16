"""Reporting helpers for tagged matches."""
from __future__ import annotations

from typing import Iterable, List

from hexpose.tag import TaggedMatch, all_tags


def _colorize(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_tagged_match(tm: TaggedMatch, *, color: bool = True) -> str:
    tag_str = ", ".join(sorted(tm.tags)) if tm.tags else "(none)"
    if color:
        tag_str = _colorize(tag_str, "36")
    return (
        f"[{tm.match.pattern_name}] "
        f"offset={tm.match.offset} "
        f"value={tm.match.value!r} "
        f"tags={tag_str}"
    )


def format_tag_report(tagged: List[TaggedMatch], *, color: bool = True) -> str:
    if not tagged:
        return "No tagged matches."
    lines = [format_tagged_match(t, color=color) for t in tagged]
    tags = all_tags(tagged)
    tag_summary = ", ".join(sorted(tags)) if tags else "(none)"
    lines.append(f"\nUnique tags: {tag_summary}")
    return "\n".join(lines)


def tag_summary(tagged: Iterable[TaggedMatch]) -> dict:
    lst = list(tagged)
    tags = all_tags(lst)
    by_tag: dict = {t: 0 for t in tags}
    for tm in lst:
        for t in tm.tags:
            by_tag[t] += 1
    return {"total": len(lst), "unique_tags": len(tags), "counts": by_tag}
