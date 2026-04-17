"""Utilities for locating matches within binary/text data."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class MatchLocation:
    offset: int          # byte offset in the source
    line_number: int     # 1-based line number (0 if not applicable)
    column: int          # 0-based column within the line
    source_path: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "offset": self.offset,
            "line_number": self.line_number,
            "column": self.column,
            "source_path": self.source_path,
        }

    def __str__(self) -> str:
        path = self.source_path or "<unknown>"
        return f"{path}:{self.line_number}:{self.column} (offset {self.offset})"


def locate_match(data: bytes, offset: int, source_path: Optional[str] = None) -> MatchLocation:
    """Compute the line/column for a byte offset inside *data*."""
    if not data:
        return MatchLocation(offset=offset, line_number=1, column=0, source_path=source_path)

    prefix = data[:offset]
    line_number = prefix.count(b"\n") + 1
    last_newline = prefix.rfind(b"\n")
    column = offset - (last_newline + 1)
    return MatchLocation(
        offset=offset,
        line_number=line_number,
        column=column,
        source_path=source_path,
    )


def locate_all(data: bytes, offsets: list, source_path: Optional[str] = None) -> list:
    """Return a MatchLocation for each offset in *offsets*."""
    return [locate_match(data, off, source_path) for off in offsets]
