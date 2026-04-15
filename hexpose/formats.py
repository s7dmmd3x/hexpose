"""File format detection helpers for hexpose."""

from __future__ import annotations

from pathlib import Path

# Magic bytes -> format name
_MAGIC: list[tuple[bytes, str]] = [
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xca\xfe\xba\xbe", "macho_fat"),
    (b"\xcf\xfa\xed\xfe", "macho64"),
    (b"\xce\xfa\xed\xfe", "macho32"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"%PDF", "pdf"),
]


def detect_format(data: bytes) -> str:
    """Return a short format name for *data* based on magic bytes.

    Falls back to ``'raw'`` when no magic matches.
    """
    for magic, name in _MAGIC:
        if data.startswith(magic):
            return name
    return "raw"


def detect_format_from_path(path: str | Path) -> str:
    """Detect format by reading the first 16 bytes of *path*."""
    p = Path(path)
    with p.open("rb") as fh:
        header = fh.read(16)
    return detect_format(header)


def is_binary(data: bytes, sample: int = 512) -> bool:
    """Heuristic: return True when *data* looks like binary (non-text) content."""
    chunk = data[:sample]
    if not chunk:
        return False
    # Files with a high ratio of null bytes or non-printable bytes are binary.
    non_printable = sum(
        1 for b in chunk if b < 0x09 or (0x0E <= b <= 0x1F) or b == 0x7F
    )
    return (non_printable / len(chunk)) > 0.10
