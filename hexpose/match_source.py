"""match_source.py — attach source provenance metadata to a Match."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from hexpose.scanner import Match


@dataclass
class SourcedMatch:
    match: Match
    source_path: Optional[str] = None
    source_type: str = "unknown"  # e.g. 'file', 'memory_dump', 'stdin'
    file_size: Optional[int] = None
    sha256: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "source_path": self.source_path,
            "source_type": self.source_type,
            "file_size": self.file_size,
            "sha256": self.sha256,
        }


def _sha256_of(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def source_match(
    match: Match,
    source_path: Optional[str] = None,
    source_type: str = "unknown",
    raw_bytes: Optional[bytes] = None,
) -> SourcedMatch:
    """Wrap *match* with provenance information derived from *source_path* / *raw_bytes*."""
    file_size: Optional[int] = None
    sha256: Optional[str] = None

    if raw_bytes is not None:
        file_size = len(raw_bytes)
        sha256 = _sha256_of(raw_bytes)
    elif source_path is not None:
        p = Path(source_path)
        if p.exists():
            data = p.read_bytes()
            file_size = len(data)
            sha256 = _sha256_of(data)

    return SourcedMatch(
        match=match,
        source_path=source_path,
        source_type=source_type,
        file_size=file_size,
        sha256=sha256,
    )


def source_all(
    matches: list[Match],
    source_path: Optional[str] = None,
    source_type: str = "unknown",
    raw_bytes: Optional[bytes] = None,
) -> list[SourcedMatch]:
    """Apply :func:`source_match` to every match in *matches*."""
    # compute sha256/size once
    file_size: Optional[int] = None
    sha256: Optional[str] = None

    if raw_bytes is not None:
        file_size = len(raw_bytes)
        sha256 = _sha256_of(raw_bytes)
    elif source_path is not None:
        p = Path(source_path)
        if p.exists():
            data = p.read_bytes()
            file_size = len(data)
            sha256 = _sha256_of(data)

    return [
        SourcedMatch(
            match=m,
            source_path=source_path,
            source_type=source_type,
            file_size=file_size,
            sha256=sha256,
        )
        for m in matches
    ]
