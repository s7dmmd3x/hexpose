"""Diff report: format and display baseline diff results."""
from __future__ import annotations
from dataclasses import dataclass
from typing import List
from hexpose.scanner import Match


@dataclass
class DiffReport:
    new_matches: List[Match]
    resolved_matches: List[Match]

    @property
    def has_new(self) -> bool:
        return len(self.new_matches) > 0

    @property
    def has_resolved(self) -> bool:
        return len(self.resolved_matches) > 0


def build_diff_report(current_matches: List[Match], baseline_fps: set) -> DiffReport:
    """Split current matches into new vs previously-known."""
    from hexpose.suppress import _fingerprint

    new: List[Match] = []
    resolved_fps = set(baseline_fps)

    for m in current_matches:
        fp = _fingerprint(m)
        if fp in baseline_fps:
            resolved_fps.discard(fp)
        else:
            new.append(m)

    # resolved = fingerprints in baseline no longer appearing in current scan
    resolved: List[Match] = []  # we only have fingerprints, not full Match objects
    return DiffReport(new_matches=new, resolved_matches=resolved)


def format_diff_report(report: DiffReport, color: bool = True) -> str:
    lines: List[str] = []

    def _c(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    lines.append(_c(f"=== Baseline Diff ===", "1"))
    lines.append(_c(f"  New findings   : {len(report.new_matches)}", "31" if report.has_new else "32"))
    lines.append(_c(f"  Resolved       : {len(report.resolved_matches)}", "32"))

    if report.new_matches:
        lines.append("")
        lines.append(_c("New findings:", "31"))
        for m in report.new_matches:
            val = m.value[:40] + "..." if len(m.value) > 40 else m.value
            lines.append(f"  [{m.pattern_name}] offset={m.offset} value={val!r}")

    return "\n".join(lines)
