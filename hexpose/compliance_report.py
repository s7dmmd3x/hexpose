"""Compliance report formatting for hexpose."""
from __future__ import annotations

from typing import List

from hexpose.match_compliance import ComplianceMatch

try:
    from colorama import Fore, Style
    _COLOUR = True
except ImportError:  # pragma: no cover
    _COLOUR = False


def _c(text: str, colour: str) -> str:
    if _COLOUR:
        return f"{colour}{text}{Style.RESET_ALL}"
    return text


def format_compliance_match(cm: ComplianceMatch) -> str:
    """Return a single-line human-readable string for *cm*."""
    fw_str = ", ".join(cm.frameworks) if cm.frameworks else "none"
    name = _c(cm.match.pattern_name, Fore.CYAN if _COLOUR else "")
    sev = _c(cm.match.severity.upper(), Fore.YELLOW if _COLOUR else "")
    fw = _c(fw_str, Fore.GREEN if _COLOUR else "")
    return f"{name} [{sev}] — frameworks: {fw}"


def format_compliance_report(matches: List[ComplianceMatch]) -> str:
    """Return a multi-line compliance report string."""
    if not matches:
        return "No compliance-mapped matches found."
    lines = ["Compliance Report", "=" * 40]
    for cm in matches:
        lines.append(format_compliance_match(cm))
    return "\n".join(lines)


def compliance_summary(matches: List[ComplianceMatch]) -> str:
    """Return a short summary line for *matches*."""
    if not matches:
        return "Compliance: 0 matches across 0 frameworks."
    all_fw: set[str] = set()
    for cm in matches:
        all_fw.update(cm.frameworks)
    return (
        f"Compliance: {len(matches)} match(es) spanning "
        f"{len(all_fw)} framework(s): {', '.join(sorted(all_fw))}"
    )
