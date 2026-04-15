"""Core scanning logic: read binary/text data and match secret patterns."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from hexpose.patterns import SecretPattern, load_patterns


@dataclass
class Match:
    pattern_name: str
    severity: str
    description: str
    offset: int
    value: str
    line_number: Optional[int] = None


@dataclass
class ScanResult:
    path: str
    matches: List[Match] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.matches) > 0


class Scanner:
    """Scan a file or raw bytes for embedded secrets."""

    def __init__(self, patterns: Optional[List[SecretPattern]] = None) -> None:
        self.patterns = patterns if patterns is not None else load_patterns()

    def scan_bytes(self, data: bytes, source: str = "<memory>") -> ScanResult:
        """Scan raw bytes decoded as UTF-8 (errors ignored)."""
        text = data.decode("utf-8", errors="replace")
        return self._scan_text(text, source)

    def scan_file(self, path: Path) -> ScanResult:
        """Read and scan a file from disk."""
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise IOError(f"Cannot read file '{path}': {exc}") from exc
        return self.scan_bytes(data, source=str(path))

    def _scan_text(self, text: str, source: str) -> ScanResult:
        result = ScanResult(path=source)
        lines = text.splitlines(keepends=True)
        # Build offset -> line number mapping
        offset_map: List[int] = []
        cumulative = 0
        for line in lines:
            offset_map.append(cumulative)
            cumulative += len(line)

        for pattern in self.patterns:
            for m in pattern.pattern.finditer(text):
                line_no = self._offset_to_line(m.start(), offset_map)
                result.matches.append(
                    Match(
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        description=pattern.description,
                        offset=m.start(),
                        value=m.group(0)[:120],  # truncate very long values
                        line_number=line_no,
                    )
                )
        return result

    @staticmethod
    def _offset_to_line(offset: int, offset_map: List[int]) -> int:
        """Return 1-based line number for a byte offset."""
        lo, hi = 0, len(offset_map) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if offset_map[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1
