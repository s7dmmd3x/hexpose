"""scope_report.py – formatting helpers for ScopedMatch results."""
from __future__ import annotations

from collections import defaultdict

from hexpose.match_scope import ScopedMatch

_RESET = "\033[0m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"
_YELLOW = "\033[33m"


def _c(code: str, text: str) -> str:
    return f"{code}{text}{_RESET}"


def format_scoped_match(sm: ScopedMatch) -> str:
    scope_label = _c(_CYAN, f"[{sm.scope}]")
    name = _c(_BOLD, sm.match.pattern_name)
    sev = _c(_YELLOW, sm.match.severity)
    offset = sm.match.offset
    value = sm.match.value[:40] + ("…" if len(sm.match.value) > 40 else "")
    return f"{scope_label} {name} severity={sev} offset={offset} value={value!r}"


def format_scope_report(scoped_matches: list[ScopedMatch]) -> str:
    if not scoped_matches:
        return "No scoped matches."
    lines = [_c(_BOLD, "Scope Report"), ""]
    for sm in scoped_matches:
        lines.append(format_scoped_match(sm))
    return "\n".join(lines)


def scope_summary(scoped_matches: list[ScopedMatch]) -> str:
    """Return a summary grouped by scope name."""
    groups: dict[str, int] = defaultdict(int)
    for sm in scoped_matches:
        groups[sm.scope] += 1
    if not groups:
        return "No matches."
    lines = [_c(_BOLD, "Scope Summary")]
    for scope, count in sorted(groups.items()):
        lines.append(f"  {_c(_CYAN, scope)}: {count} match(es)")
    return "\n".join(lines)
