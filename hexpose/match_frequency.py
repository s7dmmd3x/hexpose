"""Track how frequently each pattern appears across scan results."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from hexpose.scanner import Match, ScanResult


@dataclass
class FrequencyRecord:
    pattern_name: str
    count: int
    results_seen: int

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.pattern_name,
            "count": self.count,
            "results_seen": self.results_seen,
        }


@dataclass
class FrequencyReport:
    records: List[FrequencyRecord] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.records)

    def top(self, n: int = 5) -> List[FrequencyRecord]:
        return sorted(self.records, key=lambda r: r.count, reverse=True)[:n]

    def as_dict(self) -> dict:
        return {"records": [r.as_dict() for r in self.records]}


def build_frequency_report(results: Sequence[ScanResult]) -> FrequencyReport:
    """Count pattern occurrences across one or more ScanResults."""
    total_counts: Counter = Counter()
    result_counts: Counter = Counter()

    for result in results:
        seen_in_result: set = set()
        for match in result.matches:
            total_counts[match.pattern_name] += 1
            seen_in_result.add(match.pattern_name)
        for name in seen_in_result:
            result_counts[name] += 1

    records = [
        FrequencyRecord(
            pattern_name=name,
            count=total_counts[name],
            results_seen=result_counts[name],
        )
        for name in total_counts
    ]
    records.sort(key=lambda r: r.count, reverse=True)
    return FrequencyReport(records=records)


def pattern_frequency(results: Sequence[ScanResult]) -> Dict[str, int]:
    """Return a plain dict mapping pattern name to total match count."""
    report = build_frequency_report(results)
    return {r.pattern_name: r.count for r in report.records}
