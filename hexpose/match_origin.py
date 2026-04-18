"""Attach origin metadata (region, environment, host) to a match."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, List

from hexpose.scanner import Match, ScanResult


@dataclass
class OriginMatch:
    match: Match
    host: Optional[str] = None
    environment: Optional[str] = None
    region: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
            "host": self.host,
            "environment": self.environment,
            "region": self.region,
            "tags": list(self.tags),
        }

    def __str__(self) -> str:
        parts = [f"[{self.match.severity}] {self.match.pattern_name}"]
        if self.host:
            parts.append(f"host={self.host}")
        if self.environment:
            parts.append(f"env={self.environment}")
        if self.region:
            parts.append(f"region={self.region}")
        return " ".join(parts)


def attach_origin(
    match: Match,
    *,
    host: Optional[str] = None,
    environment: Optional[str] = None,
    region: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> OriginMatch:
    """Wrap *match* with origin metadata."""
    return OriginMatch(
        match=match,
        host=host,
        environment=environment,
        region=region,
        tags=list(tags) if tags else [],
    )


def attach_origin_all(
    result: ScanResult,
    *,
    host: Optional[str] = None,
    environment: Optional[str] = None,
    region: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> List[OriginMatch]:
    """Attach origin metadata to every match in *result*."""
    return [
        attach_origin(m, host=host, environment=environment, region=region, tags=tags)
        for m in result.matches
    ]
