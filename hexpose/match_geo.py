"""Geo-tagging for matches: attach geographic/network location metadata."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List
from hexpose.scanner import Match


@dataclass
class GeoMatch:
    match: Match
    ip_address: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "severity": self.match.severity,
            "ip_address": self.ip_address,
            "country": self.country,
            "region": self.region,
            "city": self.city,
            "asn": self.asn,
            "tags": list(self.tags),
        }

    def __str__(self) -> str:
        loc = ", ".join(filter(None, [self.city, self.region, self.country]))
        return f"{self.match.pattern_name} @ {loc or 'unknown location'}"


def attach_geo(
    match: Match,
    *,
    ip_address: Optional[str] = None,
    country: Optional[str] = None,
    region: Optional[str] = None,
    city: Optional[str] = None,
    asn: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> GeoMatch:
    """Wrap a Match with geographic metadata."""
    return GeoMatch(
        match=match,
        ip_address=ip_address,
        country=country,
        region=region,
        city=city,
        asn=asn,
        tags=[t.strip().lower() for t in (tags or []) if t.strip()],
    )


def attach_geo_all(
    matches: List[Match],
    **kwargs,
) -> List[GeoMatch]:
    """Apply attach_geo to every match with the same kwargs."""
    return [attach_geo(m, **kwargs) for m in matches]
