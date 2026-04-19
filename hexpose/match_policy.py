"""match_policy.py – policy-based match evaluation.

A Policy is a named set of rules that accepts or rejects a Match based
on severity thresholds, pattern allow/deny lists, and entropy bounds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from hexpose.scanner import Match
from hexpose.entropy import shannon_entropy


@dataclass
class Policy:
    name: str
    min_severity: int = 0          # 0=low, 1=medium, 2=high, 3=critical
    deny_patterns: List[str] = field(default_factory=list)
    allow_patterns: List[str] = field(default_factory=list)  # empty = all allowed
    min_entropy: float = 0.0
    max_entropy: float = 8.0

    def evaluate(self, match: Match) -> "PolicyResult":
        reasons: List[str] = []

        sev_order = ["low", "medium", "high", "critical"]
        try:
            sev_idx = sev_order.index(match.severity.lower())
        except ValueError:
            sev_idx = 0

        if sev_idx < self.min_severity:
            reasons.append(
                f"severity '{match.severity}' below minimum '{sev_order[self.min_severity]}'"
            )

        if self.deny_patterns and match.pattern_name in self.deny_patterns:
            reasons.append(f"pattern '{match.pattern_name}' is denied")

        if self.allow_patterns and match.pattern_name not in self.allow_patterns:
            reasons.append(f"pattern '{match.pattern_name}' not in allow list")

        ent = shannon_entropy(match.value.encode())
        if ent < self.min_entropy:
            reasons.append(f"entropy {ent:.2f} below minimum {self.min_entropy:.2f}")
        if ent > self.max_entropy:
            reasons.append(f"entropy {ent:.2f} above maximum {self.max_entropy:.2f}")

        passed = len(reasons) == 0
        return PolicyResult(match=match, policy_name=self.name, passed=passed, reasons=reasons)


@dataclass
class PolicyResult:
    match: Match
    policy_name: str
    passed: bool
    reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "policy": self.policy_name,
            "passed": self.passed,
            "pattern_name": self.match.pattern_name,
            "severity": self.match.severity,
            "reasons": self.reasons,
        }


def evaluate_all(matches: Iterable[Match], policy: Policy) -> List[PolicyResult]:
    return [policy.evaluate(m) for m in matches]


def failing(results: Iterable[PolicyResult]) -> List[PolicyResult]:
    return [r for r in results if not r.passed]


def passing(results: Iterable[PolicyResult]) -> List[PolicyResult]:
    return [r for r in results if r.passed]
