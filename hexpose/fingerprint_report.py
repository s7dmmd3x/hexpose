"""Human-readable reporting for fingerprinted matches."""
from __future__ import annotations

from typing import List

from hexpose.match_fingerprint import FingerprintedMatch


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_fingerprinted_match(fm: FingerprintedMatch, *, color: bool = True) -> str:
    fp_short = fm.fingerprint[:12]
    name = fm.match.pattern_name
    value = fm.match.value[:40] + ("…" if len(fm.match.value) > 40 else "")
    offset = fm.match.offset

    if color:
        fp_short = _c(fp_short, "36")
        name = _c(name, "33")
    return f"[{fp_short}] {name} @ offset {offset}: {value}"


def format_fingerprint_report(
    fms: List[FingerprintedMatch], *, color: bool = True
) -> str:
    if not fms:
        return "No fingerprinted matches."
    lines = [format_fingerprinted_match(fm, color=color) for fm in fms]
    return "\n".join(lines)


def fingerprint_summary(fms: List[FingerprintedMatch]) -> str:
    total = len(fms)
    unique = len({fm.fingerprint for fm in fms})
    return f"Fingerprinted matches: {total} total, {unique} unique"
