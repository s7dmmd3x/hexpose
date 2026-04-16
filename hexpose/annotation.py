"""Match annotation support — attach arbitrary metadata to matches."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hexpose.scanner import Match


@dataclass
class AnnotatedMatch:
    match: Match
    annotations: dict[str, Any] = field(default_factory=dict)

    def annotate(self, key: str, value: Any) -> None:
        """Add or overwrite a single annotation."""
        self.annotations[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.annotations.get(key, default)

    def as_dict(self) -> dict[str, Any]:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "annotations": dict(self.annotations),
        }


def annotate_match(match: Match, **kwargs: Any) -> AnnotatedMatch:
    """Wrap a Match in an AnnotatedMatch, optionally seeding annotations."""
    am = AnnotatedMatch(match=match)
    for k, v in kwargs.items():
        am.annotate(k, v)
    return am


def annotate_matches(
    matches: list[Match], **kwargs: Any
) -> list[AnnotatedMatch]:
    """Bulk-annotate a list of matches with the same key/value pairs."""
    return [annotate_match(m, **kwargs) for m in matches]


def merge_annotations(
    base: AnnotatedMatch, extra: dict[str, Any]
) -> AnnotatedMatch:
    """Return a new AnnotatedMatch with extra annotations merged in."""
    merged = AnnotatedMatch(match=base.match, annotations=dict(base.annotations))
    for k, v in extra.items():
        merged.annotate(k, v)
    return merged
