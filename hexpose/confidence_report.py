"""Formatting helpers for confidence results."""
from hexpose.confidence import ConfidenceResult

_COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[92m", "reset": "\033[0m"}


def _colorize(text: str, level: str) -> str:
    c = _COLORS.get(level, "")
    return f"{c}{text}{_COLORS['reset']}" if c else text


def format_confidence_result(cr: ConfidenceResult, color: bool = True) -> str:
    tag = f"[{cr.level.upper()}]"
    if color:
        tag = _colorize(tag, cr.level)
    reasons = ", ".join(cr.reasons) if cr.reasons else "none"
    return (
        f"{tag} {cr.match.pattern_name} "
        f"score={cr.score:.2f} offset={cr.match.offset} "
        f"reasons=[{reasons}]"
    )


def format_confidence_report(results: list, color: bool = True) -> str:
    if not results:
        return "No matches to report."
    lines = [format_confidence_result(r, color=color) for r in results]
    return "\n".join(lines)


def confidence_summary(results: list) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    for r in results:
        counts[r.level] = counts.get(r.level, 0) + 1
    return {"total": len(results), "by_level": counts}
