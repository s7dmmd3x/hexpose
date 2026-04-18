"""Track provenance (origin metadata) for each match."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class ProvenanceMatch:
    match: Match
    source_file: str
    scan_tool: str
    scan_version: str
    command_line: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "source_file": self.source_file,
            "scan_tool": self.scan_tool,
            "scan_version": self.scan_version,
            "command_line": self.command_line,
            "extra": self.extra,
        }


def attach_provenance(
    match: Match,
    source_file: str,
    scan_tool: str = "hexpose",
    scan_version: str = "unknown",
    command_line: Optional[str] = None,
    **extra,
) -> ProvenanceMatch:
    return ProvenanceMatch(
        match=match,
        source_file=source_file,
        scan_tool=scan_tool,
        scan_version=scan_version,
        command_line=command_line,
        extra=extra,
    )


def attach_provenance_all(
    result: ScanResult,
    source_file: str,
    scan_tool: str = "hexpose",
    scan_version: str = "unknown",
    command_line: Optional[str] = None,
    **extra,
) -> list[ProvenanceMatch]:
    return [
        attach_provenance(
            m,
            source_file=source_file,
            scan_tool=scan_tool,
            scan_version=scan_version,
            command_line=command_line,
            **extra,
        )
        for m in result.matches
    ]
