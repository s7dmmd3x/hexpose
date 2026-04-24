"""Formatting helpers for CVE-annotated matches."""
from __future__ import annotations

from typing import List

from hexpose.match_cve import CVEMatch

try:
    import colorama  # type: ignore
    _RED = colorama.Fore.RED
    _YELLOW = colorama.Fore.YELLOW
    _CYAN = colorama.Fore.CYAN
    _RESET = colorama.Style.RESET_ALL
except ImportError:  # pragma: no cover
    _RED = _YELLOW = _CYAN = _RESET = ""


def _c(text: str, colour: str) -> str:
    return f"{colour}{text}{_RESET}" if colour else text


def format_cve_match(cm: CVEMatch) -> str:
    """Return a single-line summary of a CVE-annotated match."""
    name = _c(cm.match.pattern_name, _CYAN)
    severity = _c(cm.match.severity, _RED)
    if cm.cves:
        cve_str = _c(", ".join(cm.cves), _YELLOW)
    else:
        cve_str = "(no CVEs)"
    line = f"{name} [{severity}] CVEs: {cve_str}"
    if cm.reference_url:
        line += f"  ref: {cm.reference_url}"
    return line


def format_cve_report(cve_matches: List[CVEMatch]) -> str:
    """Return a multi-line report for a list of CVE-annotated matches."""
    if not cve_matches:
        return "No CVE-annotated matches."
    lines = ["CVE Report", "=" * 40]
    for cm in cve_matches:
        lines.append(format_cve_match(cm))
    return "\n".join(lines)


def cve_summary(cve_matches: List[CVEMatch]) -> str:
    """Return a one-line summary: total matches and unique CVE count."""
    total = len(cve_matches)
    unique_cves: set[str] = set()
    for cm in cve_matches:
        unique_cves.update(cm.cves)
    return f"{total} match(es) with {len(unique_cves)} unique CVE(s) referenced."
