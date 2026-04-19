"""Formatting helpers for VerdictMatch results."""
from __future__ import annotations
from hexpose.match_verdict import VerdictMatch, VERDICT_CONFIRMED, VERDICT_LIKELY, VERDICT_UNCERTAIN

_ANSI = {
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
    "reset": "\033[0m",
}


def _c(text: str, colour: str) -> str:
    return f"{_ANSI.get(colour, '')}{text}{_ANSI['reset']}"


def format_verdict_match(vm: VerdictMatch) -> str:
    colour_map = {
        VERDICT_CONFIRMED: "red",
        VERDICT_LIKELY: "yellow",
        VERDICT_UNCERTAIN: "cyan",
    }
    colour = colour_map.get(vm.verdict, "grey")
    verdict_str = _c(vm.verdict.upper(), colour)
    return (
        f"[{verdict_str}] {vm.match.pattern_name} "
        f"@ offset {vm.match.offset} "
        f"(confidence={vm.confidence_score:.2f}) — {vm.reason}"
    )


def format_verdict_report(verdicts: list[VerdictMatch]) -> str:
    if not verdicts:
        return "No verdicts to display."
    lines = ["=== Verdict Report ==="]
    for vm in verdicts:
        lines.append(format_verdict_match(vm))
    return "\n".join(lines)


def verdict_summary(verdicts: list[VerdictMatch]) -> str:
    from collections import Counter
    counts: Counter = Counter(vm.verdict for vm in verdicts)
    parts = [f"{v}: {n}" for v, n in sorted(counts.items())]
    return "Verdicts — " + ", ".join(parts) if parts else "Verdicts — none"
