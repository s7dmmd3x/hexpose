"""Analyst notes attached to individual matches."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
from hexpose.scanner import Match


@dataclass
class NotedMatch:
    match: Match
    notes: List[str] = field(default_factory=list)

    def add(self, note: str) -> None:
        note = note.strip()
        if note:
            self.notes.append(note)

    def has_notes(self) -> bool:
        return bool(self.notes)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "notes": list(self.notes),
        }


def note_match(match: Match, *notes: str) -> NotedMatch:
    nm = NotedMatch(match=match)
    for n in notes:
        nm.add(n)
    return nm


def annotate_result(matches: List[Match], notes_map: dict) -> List[NotedMatch]:
    """Attach notes to matches by pattern name.

    notes_map: {pattern_name: [note, ...]}
    """
    result = []
    for m in matches:
        nm = NotedMatch(match=m)
        for note in notes_map.get(m.pattern_name, []):
            nm.add(note)
        result.append(nm)
    return result
