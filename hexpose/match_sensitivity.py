"""Sensitivity classification for matches."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from hexpose.scanner import Match

_SENSITIVITY_MAP: dict[str, str] = {
    "aws_access_key": "restricted",
    "aws_secret_key": "confidential",
    "github_token": "confidential",
    "jwt": "internal",
    "password": "confidential",
    "private_key": "confidential",
    "api_key": "restricted",
    "slack_token": "restricted",
    "stripe_key": "confidential",
    "google_api_key": "restricted",
}

_LEVELS = ("public", "internal", "restricted", "confidential")


@dataclass
class SensitivityMatch:
    match: Match
    sensitivity: str
    level: int
    notes: str = ""
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "sensitivity": self.sensitivity,
            "level": self.level,
            "notes": self.notes,
        }

    def __str__(self) -> str:
        return f"[{self.sensitivity.upper()}] {self.match.pattern_name}"


def _resolve_sensitivity(pattern_name: str) -> str:
    key = pattern_name.lower()
    for fragment, sens in _SENSITIVITY_MAP.items():
        if fragment in key:
            return sens
    return "internal"


def classify_sensitivity(
    match: Match,
    override: Optional[str] = None,
    notes: str = "",
) -> SensitivityMatch:
    sensitivity = override.lower() if override else _resolve_sensitivity(match.pattern_name)
    if sensitivity not in _LEVELS:
        sensitivity = "internal"
    level = _LEVELS.index(sensitivity)
    return SensitivityMatch(match=match, sensitivity=sensitivity, level=level, notes=notes)


def classify_sensitivity_all(
    matches: list[Match],
    override: Optional[str] = None,
    notes: str = "",
) -> list[SensitivityMatch]:
    return [classify_sensitivity(m, override=override, notes=notes) for m in matches]
