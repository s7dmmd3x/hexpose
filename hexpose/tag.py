"""Match tagging — attach and query free-form string tags on matches."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Set

from hexpose.scanner import Match


@dataclass
class TaggedMatch:
    match: Match
    tags: Set[str] = field(default_factory=set)

    def add(self, *tags: str) -> "TaggedMatch":
        self.tags.update(t.strip().lower() for t in tags if t.strip())
        return self

    def has(self, tag: str) -> bool:
        return tag.strip().lower() in self.tags

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "tags": sorted(self.tags),
        }


def tag_match(match: Match, *tags: str) -> TaggedMatch:
    """Wrap *match* in a TaggedMatch and apply *tags*."""
    return TaggedMatch(match=match).add(*tags)


def filter_by_tag(tagged: Iterable[TaggedMatch], tag: str) -> List[TaggedMatch]:
    """Return only those TaggedMatches that carry *tag*."""
    return [t for t in tagged if t.has(tag)]


def all_tags(tagged: Iterable[TaggedMatch]) -> Set[str]:
    """Collect every unique tag present across *tagged*."""
    result: Set[str] = set()
    for t in tagged:
        result.update(t.tags)
    return result
