"""match_mask — selectively mask match values for safe display or storage."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from hexpose.scanner import Match
from hexpose.redactor import redact_value


@dataclass
class MaskedMatch:
    match: Match
    masked_value: str
    mask_mode: str
    reveal_chars: int

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "masked_value": self.masked_value,
            "mask_mode": self.mask_mode,
            "reveal_chars": self.reveal_chars,
            "offset": self.match.offset,
            "severity": self.match.severity,
        }

    def __str__(self) -> str:
        return f"[{self.match.pattern_name}] {self.masked_value} (mode={self.mask_mode})"


def mask_match(
    match: Match,
    mode: str = "partial",
    reveal_chars: int = 4,
) -> MaskedMatch:
    """Return a MaskedMatch wrapping *match* with its value obscured.

    mode:
        'full'    — replace entire value with placeholder
        'partial' — keep first *reveal_chars* chars, mask the rest
    """
    if mode not in ("full", "partial"):
        raise ValueError(f"Unknown mask mode: {mode!r}")
    masked = redact_value(match.value, mode=mode)
    return MaskedMatch(
        match=match,
        masked_value=masked,
        mask_mode=mode,
        reveal_chars=reveal_chars if mode == "partial" else 0,
    )


def mask_all(
    matches: list[Match],
    mode: str = "partial",
    reveal_chars: int = 4,
) -> list[MaskedMatch]:
    """Mask every match in *matches*."""
    return [mask_match(m, mode=mode, reveal_chars=reveal_chars) for m in matches]
