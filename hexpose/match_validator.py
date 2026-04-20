"""match_validator.py – validate matches against configurable rules.

A ValidatedMatch wraps a Match with a list of validation errors (if any).
A match is considered valid when no rules are violated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class ValidatedMatch:
    match: Match
    errors: List[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "is_valid": self.is_valid,
            "errors": list(self.errors),
        }


def _check_min_length(match: Match, min_length: int) -> Optional[str]:
    if len(match.value) < min_length:
        return f"value length {len(match.value)} is below minimum {min_length}"
    return None


def _check_max_length(match: Match, max_length: int) -> Optional[str]:
    if len(match.value) > max_length:
        return f"value length {len(match.value)} exceeds maximum {max_length}"
    return None


def _check_non_empty(match: Match) -> Optional[str]:
    if not match.value.strip():
        return "value is empty or whitespace-only"
    return None


def _check_allowed_severities(
    match: Match, allowed: List[str]
) -> Optional[str]:
    if match.severity not in allowed:
        return f"severity '{match.severity}' not in allowed set {allowed}"
    return None


def validate_match(
    match: Match,
    *,
    min_length: int = 1,
    max_length: int = 4096,
    allowed_severities: Optional[List[str]] = None,
) -> ValidatedMatch:
    """Run all configured validation rules against *match*."""
    errors: List[str] = []

    err = _check_non_empty(match)
    if err:
        errors.append(err)

    err = _check_min_length(match, min_length)
    if err:
        errors.append(err)

    err = _check_max_length(match, max_length)
    if err:
        errors.append(err)

    if allowed_severities is not None:
        err = _check_allowed_severities(match, allowed_severities)
        if err:
            errors.append(err)

    return ValidatedMatch(match=match, errors=errors)


def validate_result(
    result: ScanResult,
    **kwargs,
) -> List[ValidatedMatch]:
    """Validate every match in *result* and return a list of ValidatedMatch."""
    return [validate_match(m, **kwargs) for m in result.matches]
