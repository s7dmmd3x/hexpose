"""signal_report.py – human-readable formatting for SignalMatch results."""
from __future__ import annotations

from typing import List

from hexpose.match_signal import SignalMatch

_ANSI = {
    "strong":   "\033[91m",  # bright red
    "moderate": "\033[93m",  # yellow
    "weak":     "\033[92m",  # green
    "reset":    "\033[0m",
}


def _c(label: str, text: str) -> str:
    return f"{_ANSI.get(label, '')}{text}{_ANSI['reset']}"


def format_signal_match(sm: SignalMatch, *, color: bool = True) -> str:
    label = sm.signal_label
    tag = _c(label, f"[{label.upper()}]") if color else f"[{label.upper()}]"
    return (
        f"{tag} {sm.match.pattern_name} "
        f"score={sm.signal_score:.3f} "
        f"entropy={sm.entropy:.3f} "
        f"sev={sm.match.severity or 'unknown'}"
    )


def format_signal_report(
    signals: List[SignalMatch],
    *,
    color: bool = True,
) -> str:
    if not signals:
        return "No signals found."
    lines = ["=== Signal Report ==="]
    for sm in sorted(signals, key=lambda s: s.signal_score, reverse=True):
        lines.append("  " + format_signal_match(sm, color=color))
    return "\n".join(lines)


def signal_summary(signals: List[SignalMatch]) -> str:
    if not signals:
        return "Signals: 0"
    strong   = sum(1 for s in signals if s.signal_label == "strong")
    moderate = sum(1 for s in signals if s.signal_label == "moderate")
    weak     = sum(1 for s in signals if s.signal_label == "weak")
    return (
        f"Signals: {len(signals)} total "
        f"(strong={strong}, moderate={moderate}, weak={weak})"
    )
