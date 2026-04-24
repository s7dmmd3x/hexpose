"""CVE association for matches — links a match to known CVE identifiers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from hexpose.scanner import Match, ScanResult

# Rough mapping from pattern name keywords to CVE IDs (illustrative, not exhaustive)
_PATTERN_CVE_MAP: dict[str, List[str]] = {
    "aws": ["CVE-2020-15228"],
    "github": ["CVE-2021-41599"],
    "jwt": ["CVE-2018-1000531"],
    "rsa_private": ["CVE-2016-6313"],
    "google_api": ["CVE-2019-11248"],
    "stripe": ["CVE-2020-28243"],
    "slack": ["CVE-2021-32640"],
    "password": ["CVE-2019-14234"],
}


def _lookup_cves(pattern_name: str) -> List[str]:
    """Return CVE IDs associated with *pattern_name* (case-insensitive keyword match)."""
    lower = pattern_name.lower()
    for keyword, cves in _PATTERN_CVE_MAP.items():
        if keyword in lower:
            return list(cves)
    return []


@dataclass
class CVEMatch:
    """A *Match* decorated with associated CVE identifiers."""

    match: Match
    cves: List[str] = field(default_factory=list)
    reference_url: Optional[str] = None

    def as_dict(self) -> dict:
        base = self.match.__dict__.copy()
        base["cves"] = list(self.cves)
        base["cve_reference_url"] = self.reference_url
        return base

    def __str__(self) -> str:
        cve_str = ", ".join(self.cves) if self.cves else "none"
        return f"[{self.match.pattern_name}] CVEs: {cve_str}"


def attach_cve(
    match: Match,
    *,
    extra_cves: Optional[List[str]] = None,
    reference_url: Optional[str] = None,
) -> CVEMatch:
    """Attach CVE information to *match*."""
    cves = _lookup_cves(match.pattern_name)
    if extra_cves:
        for c in extra_cves:
            c = c.strip()
            if c and c not in cves:
                cves.append(c)
    return CVEMatch(match=match, cves=cves, reference_url=reference_url)


def attach_cve_all(
    result: ScanResult,
    *,
    extra_cves: Optional[List[str]] = None,
    reference_url: Optional[str] = None,
) -> List[CVEMatch]:
    """Attach CVE information to every match in *result*."""
    return [
        attach_cve(m, extra_cves=extra_cves, reference_url=reference_url)
        for m in result.matches
    ]
