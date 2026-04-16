"""Summary statistics for scan results."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List
from hexpose.scanner import ScanResult, Match


@dataclass
class ScanSummary:
    total_matches: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_pattern: Dict[str, int] = field(default_factory=dict)
    unique_values: int = 0
    files_scanned: int = 0
    files_with_findings: int = 0

    def as_dict(self) -> dict:
        return {
            "total_matches": self.total_matches,
            "by_severity": self.by_severity,
            "by_pattern": self.by_pattern,
            "unique_values": self.unique_values,
            "files_scanned": self.files_scanned,
            "files_with_findings": self.files_with_findings,
        }


def summarize(results: List[ScanResult]) -> ScanSummary:
    """Compute summary statistics across one or more ScanResults."""
    summary = ScanSummary(files_scanned=len(results))
    seen_values: set = set()

    for result in results:
        matches: List[Match] = result.matches
        if matches:
            summary.files_with_findings += 1
        for m in matches:
            summary.total_matches += 1
            sev = str(m.severity) if m.severity else "unknown"
            summary.by_severity[sev] = summary.by_severity.get(sev, 0) + 1
            name = m.pattern_name or "unknown"
            summary.by_pattern[name] = summary.by_pattern.get(name, 0) + 1
            seen_values.add(m.value)

    summary.unique_values = len(seen_values)
    return summary


def format_summary(summary: ScanSummary) -> str:
    """Return a human-readable summary string."""
    lines = [
        f"Files scanned  : {summary.files_scanned}",
        f"Files with hits: {summary.files_with_findings}",
        f"Total matches  : {summary.total_matches}",
        f"Unique values  : {summary.unique_values}",
    ]
    if summary.by_severity:
        lines.append("By severity    : " + ", ".join(f"{k}={v}" for k, v in sorted(summary.by_severity.items())))
    if summary.by_pattern:
        lines.append("By pattern     : " + ", ".join(f"{k}={v}" for k, v in sorted(summary.by_pattern.items())))
    return "\n".join(lines)
