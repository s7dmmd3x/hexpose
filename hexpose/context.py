"""Context extraction: retrieve surrounding bytes/lines around a match."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class MatchContext:
    """Surrounding context for a single match."""

    before_lines: List[str] = field(default_factory=list)
    match_line: str = ""
    after_lines: List[str] = field(default_factory=list)
    line_number: Optional[int] = None

    def as_text(self, mark: bool = True) -> str:
        """Render context as a human-readable block."""
        lines = []
        for ln in self.before_lines:
            lines.append(f"  {ln}")
        prefix = "> " if mark else "  "
        lines.append(f"{prefix}{self.match_line}")
        for ln in self.after_lines:
            lines.append(f"  {ln}")
        return "\n".join(lines)


def extract_context(
    data: bytes,
    offset: int,
    match_length: int,
    context_lines: int = 2,
) -> MatchContext:
    """Extract *context_lines* lines before and after the line containing *offset*.

    Parameters
    ----------
    data:          Raw bytes of the scanned buffer.
    offset:        Byte offset where the match starts.
    match_length:  Length of the matched bytes.
    context_lines: Number of surrounding lines to include.
    """
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = repr(data)

    all_lines = text.splitlines()
    if not all_lines:
        return MatchContext(match_line=text)

    # Determine which line index contains our offset
    cumulative = 0
    target_idx = 0
    for idx, line in enumerate(all_lines):
        line_end = cumulative + len(line) + 1  # +1 for newline
        if cumulative <= offset < line_end:
            target_idx = idx
            break
        cumulative = line_end
    else:
        target_idx = len(all_lines) - 1

    start = max(0, target_idx - context_lines)
    end = min(len(all_lines) - 1, target_idx + context_lines)

    return MatchContext(
        before_lines=all_lines[start:target_idx],
        match_line=all_lines[target_idx],
        after_lines=all_lines[target_idx + 1 : end + 1],
        line_number=target_idx + 1,
    )
