"""Export TrendReport to JSON or CSV."""
from __future__ import annotations
import csv
import io
import json
from hexpose.trend import TrendReport


def trend_to_json(report: TrendReport, indent: int = 2) -> str:
    """Serialize a TrendReport to a JSON string."""
    return json.dumps(report.as_dict(), indent=indent)


def trend_to_csv(report: TrendReport) -> str:
    """Serialize a TrendReport to CSV.

    Columns: label, total_matches, <severity...>
    """
    if not report.points:
        return ""

    # Collect all severity keys across all points
    all_severities: list[str] = sorted(
        {sev for p in report.points for sev in p.by_severity}
    )

    buf = io.StringIO()
    fieldnames = ["label", "total_matches"] + all_severities
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for p in report.points:
        row: dict = {"label": p.label, "total_matches": p.total_matches}
        for sev in all_severities:
            row[sev] = p.by_severity.get(sev, 0)
        writer.writerow(row)
    return buf.getvalue()


def export_trend(report: TrendReport, fmt: str) -> str:
    """Export trend report in the requested format ('json' or 'csv')."""
    fmt = fmt.lower().strip()
    if fmt == "json":
        return trend_to_json(report)
    if fmt == "csv":
        return trend_to_csv(report)
    raise ValueError(f"Unsupported trend export format: {fmt!r}")
