# match_geo

Attach geographic and network location metadata to scan matches.

## Overview

`hexpose.match_geo` wraps a `Match` in a `GeoMatch` dataclass that carries
optional IP address, country, region, city, ASN, and free-form tag information.

## Usage

```python
from hexpose.match_geo import attach_geo, attach_geo_all

# Single match
geo = attach_geo(
    match,
    ip_address="203.0.113.5",
    country="US",
    region="California",
    city="San Francisco",
    asn="AS15169",
    tags=["cloud", "gcp"],
)

print(geo)          # aws_key @ San Francisco, California, US
print(geo.as_dict())

# All matches in a result
geo_matches = attach_geo_all(result.matches, country="DE")
```

## Reporting

```python
from hexpose.geo_report import format_geo_report, geo_summary

print(format_geo_report(geo_matches))
print(geo_summary(geo_matches))
```

## API

### `attach_geo(match, *, ip_address, country, region, city, asn, tags) -> GeoMatch`

All keyword arguments are optional and default to `None` / `[]`.
Tags are normalised to lowercase with surrounding whitespace stripped.

### `attach_geo_all(matches, **kwargs) -> List[GeoMatch]`

Applies `attach_geo` to every match using the same keyword arguments.

### `GeoMatch.as_dict() -> dict`

Returns a plain dictionary representation suitable for JSON serialisation.
