"""mask_report — format MaskedMatch objects for terminal output."""
from __future__ import annotations
from hexpose.match_mask import MaskedMatch

try:
    from colorama import Fore, Style
    _COLOUR = True
except ImportError:
    _COLOUR = False


def _c(text: str, colour: str) -> str:
    if not _COLOUR:
        return text
    return f"{colour}{text}{Style.RESET_ALL}"


def format_masked_match(mm: MaskedMatch) -> str:
    name = _c(mm.match.pattern_name, Fore.CYAN if _COLOUR else "")
    value = _c(mm.masked_value, Fore.YELLOW if _COLOUR else "")
    sev = _c(mm.match.severity.upper(), Fore.RED if _COLOUR else "")
    return f"  [{sev}] {name}: {value}  (mode={mm.mask_mode}, offset={mm.match.offset})"


def format_mask_report(masked: list[MaskedMatch]) -> str:
    if not masked:
        return "No masked matches."
    lines = [_c("=== Masked Matches ===", Fore.WHITE if _COLOUR else "")]
    for mm in masked:
        lines.append(format_masked_match(mm))
    return "\n".join(lines)


def mask_summary(masked: list[MaskedMatch]) -> str:
    total = len(masked)
    modes: dict[str, int] = {}
    for mm in masked:
        modes[mm.mask_mode] = modes.get(mm.mask_mode, 0) + 1
    parts = ", ".join(f"{v} {k}" for k, v in sorted(modes.items()))
    return f"Masked {total} match(es): {parts}" if parts else f"Masked {total} match(es)."
