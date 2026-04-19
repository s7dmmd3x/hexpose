"""Match quota enforcement — cap findings per pattern or overall."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from hexpose.scanner import Match, ScanResult


@dataclass
class QuotaConfig:
    max_total: Optional[int] = None
    max_per_pattern: Optional[int] = None
    per_pattern_overrides: Dict[str, int] = field(default_factory=dict)


@dataclass
class QuotaResult:
    matches: List[Match]
    dropped: int
    capped: bool

    def as_dict(self) -> dict:
        return {
            "match_count": len(self.matches),
            "dropped": self.dropped,
            "capped": self.capped,
        }


def apply_quota(matches: List[Match], config: QuotaConfig) -> QuotaResult:
    """Apply quota limits, returning a QuotaResult with surviving matches."""
    per_pattern: Dict[str, int] = {}
    kept: List[Match] = []

    for m in matches:
        name = m.pattern_name
        limit = config.per_pattern_overrides.get(name, config.max_per_pattern)
        count = per_pattern.get(name, 0)
        if limit is not None and count >= limit:
            continue
        per_pattern[name] = count + 1
        kept.append(m)

    capped = False
    if config.max_total is not None and len(kept) > config.max_total:
        kept = kept[: config.max_total]
        capped = True

    dropped = len(matches) - len(kept)
    return QuotaResult(matches=kept, dropped=dropped, capped=capped)


def apply_quota_to_result(result: ScanResult, config: QuotaConfig) -> QuotaResult:
    """Convenience wrapper that operates on a ScanResult."""
    return apply_quota(result.matches, config)
