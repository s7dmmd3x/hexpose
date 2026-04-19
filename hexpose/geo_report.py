"""Formatting helpers for GeoMatch results."""
from __future__ import annotations
from typing import List
from hexpose.match_geo import GeoMatch


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def format_geo_match(gm: GeoMatch) -> str:
    name = _c(gm.match.pattern_name, "1")
    sev = _c(gm.match.severity, "33")
    loc_parts = filter(None, [gm.city, gm.region, gm.country])
    location = _c(", ".join(loc_parts) or "unknown", "36")
    ip = f"  IP : {gm.ip_address}" if gm.ip_address else "  IP : n/a"
    asn = f"  ASN: {gm.asn}" if gm.asn else "  ASN: n/a"
    tags = f"  Tags: {', '.join(gm.tags)}" if gm.tags else ""
    lines = [f"[{sev}] {name} — {location}", ip, asn]
    if tags:
        lines.append(tags)
    return "\n".join(lines)


def format_geo_report(geo_matches: List[GeoMatch]) -> str:
    if not geo_matches:
        return "No geo-tagged matches."
    sections = [format_geo_match(gm) for gm in geo_matches]
    return "\n\n".join(sections)


def geo_summary(geo_matches: List[GeoMatch]) -> str:
    if not geo_matches:
        return "Geo summary: 0 matches."
    countries = {gm.country for gm in geo_matches if gm.country}
    return (
        f"Geo summary: {len(geo_matches)} match(es) across "
        f"{len(countries)} country/countries."
    )
