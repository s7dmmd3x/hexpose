"""Match compliance module — maps matches to regulatory frameworks."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from hexpose.scanner import Match

# Mapping from pattern name keywords to compliance frameworks
_COMPLIANCE_MAP: dict[str, List[str]] = {
    "aws": ["SOC2", "PCI-DSS", "ISO27001"],
    "github": ["SOC2", "ISO27001"],
    "jwt": ["SOC2", "GDPR", "ISO27001"],
    "password": ["PCI-DSS", "GDPR", "HIPAA", "ISO27001"],
    "private_key": ["PCI-DSS", "SOC2", "ISO27001"],
    "api_key": ["SOC2", "PCI-DSS"],
    "token": ["SOC2", "ISO27001"],
    "secret": ["SOC2", "PCI-DSS", "ISO27001"],
    "database": ["GDPR", "HIPAA", "PCI-DSS"],
    "ssn": ["GDPR", "HIPAA"],
    "credit_card": ["PCI-DSS", "GDPR"],
}

_DEFAULT_FRAMEWORKS: List[str] = ["ISO27001"]


def _lookup_frameworks(pattern_name: str) -> List[str]:
    """Return compliance frameworks relevant to *pattern_name*."""
    lower = pattern_name.lower()
    for keyword, frameworks in _COMPLIANCE_MAP.items():
        if keyword in lower:
            return list(frameworks)
    return list(_DEFAULT_FRAMEWORKS)


@dataclass
class ComplianceMatch:
    """A match decorated with applicable compliance frameworks."""

    match: Match
    frameworks: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "severity": self.match.severity,
            "frameworks": self.frameworks,
        }

    def __str__(self) -> str:  # pragma: no cover
        fw = ", ".join(self.frameworks) if self.frameworks else "none"
        return f"[{self.match.pattern_name}] frameworks={fw}"


def attach_compliance(match: Match) -> ComplianceMatch:
    """Attach compliance frameworks to *match*."""
    frameworks = _lookup_frameworks(match.pattern_name)
    return ComplianceMatch(match=match, frameworks=frameworks)


def attach_compliance_all(matches: List[Match]) -> List[ComplianceMatch]:
    """Attach compliance frameworks to every match in *matches*."""
    return [attach_compliance(m) for m in matches]
