"""Export scan results to various file formats (JSON, CSV, SARIF)."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from hexpose.scanner import ScanResult
from hexpose.redactor import apply_redaction


def _match_to_dict(match: Any, redact: bool = True, mode: str = "partial") -> dict:
    value = match.value
    if redact:
        value = apply_redaction(value, [value], mode)
    return {
        "pattern": match.pattern_name,
        "severity": match.severity,
        "offset": match.offset,
        "value": value,
        "entropy": round(match.entropy, 4) if match.entropy is not None else None,
    }


def to_json(result: ScanResult, redact: bool = True, mode: str = "partial") -> str:
    """Serialise *result* to a JSON string."""
    data = {
        "source": result.source,
        "format": result.format,
        "matches": [_match_to_dict(m, redact, mode) for m in result.matches],
    }
    return json.dumps(data, indent=2)


def to_csv(result: ScanResult, redact: bool = True, mode: str = "partial") -> str:
    """Serialise *result* to a CSV string."""
    buf = io.StringIO()
    fieldnames = ["source", "pattern", "severity", "offset", "value", "entropy"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for m in result.matches:
        row = _match_to_dict(m, redact, mode)
        row["source"] = result.source
        writer.writerow(row)
    return buf.getvalue()


def to_sarif(result: ScanResult, redact: bool = True, mode: str = "partial") -> str:
    """Serialise *result* to a minimal SARIF 2.1.0 JSON string."""
    rules = {}
    results = []
    for m in result.matches:
        rule_id = m.pattern_name
        rules[rule_id] = {
            "id": rule_id,
            "defaultConfiguration": {"level": m.severity},
        }
        value = apply_redaction(m.value, [m.value], mode) if redact else m.value
        results.append({
            "ruleId": rule_id,
            "message": {"text": value},
            "locations": [{"logicalLocations": [{"name": result.source}]}],
            "properties": {"offset": m.offset},
        })
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "hexpose", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


FORMAT_HANDLERS = {"json": to_json, "csv": to_csv, "sarif": to_sarif}


def export(result: ScanResult, fmt: str, redact: bool = True, mode: str = "partial") -> str:
    """Export *result* using *fmt*. Raises ValueError for unknown formats."""
    handler = FORMAT_HANDLERS.get(fmt)
    if handler is None:
        raise ValueError(f"Unknown export format: {fmt!r}. Choose from {list(FORMAT_HANDLERS)}.")
    return handler(result, redact, mode)


def export_all(
    result: ScanResult,
    redact: bool = True,
    mode: str = "partial",
) -> dict[str, str]:
    """Export *result* in all supported formats.

    Returns a dict mapping each format name to its serialised string.
    """
    return {fmt: handler(result, redact, mode) for fmt, handler in FORMAT_HANDLERS.items()}
