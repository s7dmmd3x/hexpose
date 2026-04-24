"""Threat intelligence enrichment for matches."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from hexpose.scanner import Match

# Lightweight static threat-intel mapping keyed on pattern name fragments.
_THREAT_MAP: dict[str, list[str]] = {
    "aws": ["TA0006", "T1552.005"],
    "github": ["TA0006", "T1552.001"],
    "jwt": ["TA0006", "T1528"],
    "password": ["TA0006", "T1552"],
    "private_key": ["TA0006", "T1552.004"],
    "stripe": ["TA0006", "T1552"],
    "slack": ["TA0006", "T1552"],
    "generic": ["TA0006"],
}

_DEFAULT_TECHNIQUES: list[str] = ["TA0006"]


def _lookup_techniques(pattern_name: str) -> list[str]:
    """Return MITRE ATT&CK technique IDs relevant to *pattern_name*."""
    lower = pattern_name.lower()
    for keyword, techniques in _THREAT_MAP.items():
        if keyword in lower:
            return list(techniques)
    return list(_DEFAULT_TECHNIQUES)


@dataclass
class ThreatMatch:
    """A match enriched with threat-intelligence metadata."""

    match: Match
    techniques: List[str] = field(default_factory=list)
    tactic: str = "Credential Access"
    threat_level: str = "medium"

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "severity": self.match.severity,
            "techniques": self.techniques,
            "tactic": self.tactic,
            "threat_level": self.threat_level,
        }

    def __str__(self) -> str:  # pragma: no cover
        techs = ", ".join(self.techniques) if self.techniques else "none"
        return (
            f"[{self.threat_level.upper()}] {self.match.pattern_name} "
            f"| tactic={self.tactic} | techniques={techs}"
        )


def _threat_level(severity: str) -> str:
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get(severity.lower(), "medium")


def attach_threat(match: Match) -> ThreatMatch:
    """Enrich *match* with threat-intelligence data."""
    techniques = _lookup_techniques(match.pattern_name)
    level = _threat_level(match.severity)
    return ThreatMatch(
        match=match,
        techniques=techniques,
        tactic="Credential Access",
        threat_level=level,
    )


def attach_threat_all(matches: list[Match]) -> list[ThreatMatch]:
    """Enrich every match in *matches* with threat-intelligence data."""
    return [attach_threat(m) for m in matches]
