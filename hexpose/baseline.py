"""Baseline management: compare current scan against a stored baseline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple

from hexpose.scanner import Match, ScanResult
from hexpose.suppress import _fingerprint


def _result_to_dict(result: ScanResult) -> dict:
    return {
        "source": result.source,
        "matches": [
            {
                "fingerprint": _fingerprint(m),
                "pattern_name": m.pattern_name,
                "offset": m.offset,
                "severity": m.severity,
            }
            for m in result.matches
        ],
    }


def save_baseline(result: ScanResult, path: str | Path) -> None:
    """Persist *result* as a baseline JSON file."""
    Path(path).write_text(json.dumps(_result_to_dict(result), indent=2))


def load_baseline_fingerprints(path: str | Path) -> set[str]:
    """Return the set of fingerprints stored in a baseline file."""
    p = Path(path)
    if not p.exists():
        return set()
    data = json.loads(p.read_text())
    return {m["fingerprint"] for m in data.get("matches", [])}


def diff_baseline(
    result: ScanResult, path: str | Path
) -> Tuple[List[Match], List[Match]]:
    """Compare *result* against a baseline.

    Returns:
        (new_matches, resolved_matches) where *new_matches* are findings not
        present in the baseline and *resolved_matches* are baseline entries no
        longer found.
    """
    baseline_fps = load_baseline_fingerprints(path)
    current_fps = {_fingerprint(m): m for m in result.matches}

    new_matches = [
        m for fp, m in current_fps.items() if fp not in baseline_fps
    ]
    resolved_fps = baseline_fps - set(current_fps.keys())
    # We can only report counts for resolved (originals are gone)
    return new_matches, list(resolved_fps)
