"""Formatting helpers for remediation hints."""
from hexpose.remediation import RemediationHint, get_hint
from hexpose.scanner import Match, ScanResult


def _colorize(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_hint(hint: RemediationHint, *, color: bool = True) -> str:
    lines = []
    title = f"[{hint.pattern_name}] {hint.summary}"
    lines.append(_colorize(title, "33") if color else title)
    for i, step in enumerate(hint.steps, 1):
        lines.append(f"  {i}. {step}")
    if hint.reference:
        ref = f"  Ref: {hint.reference}"
        lines.append(_colorize(ref, "36") if color else ref)
    return "\n".join(lines)


def format_remediation_report(
    matches: list[Match], *, color: bool = True
) -> str:
    if not matches:
        return "No findings — nothing to remediate."
    seen: set[str] = set()
    sections = []
    for m in matches:
        if m.pattern_name not in seen:
            seen.add(m.pattern_name)
            hint = get_hint(m.pattern_name)
            sections.append(format_hint(hint, color=color))
    header = _colorize("Remediation Guidance", "1;37") if color else "Remediation Guidance"
    return header + "\n" + ("\n\n".join(sections))


def remediation_summary(result: ScanResult, *, color: bool = True) -> str:
    return format_remediation_report(result.matches, color=color)
