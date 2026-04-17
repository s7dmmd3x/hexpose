"""Categorise matches into broad secret families."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict
from hexpose.scanner import Match

_CATEGORY_MAP: Dict[str, str] = {
    "aws": "cloud",
    "gcp": "cloud",
    "azure": "cloud",
    "github": "vcs",
    "gitlab": "vcs",
    "bitbucket": "vcs",
    "jwt": "auth_token",
    "bearer": "auth_token",
    "oauth": "auth_token",
    "password": "credential",
    "passwd": "credential",
    "secret": "credential",
    "api_key": "api_key",
    "apikey": "api_key",
    "private_key": "cryptographic",
    "rsa": "cryptographic",
    "ssh": "cryptographic",
}

UNKNOWN_CATEGORY = "unknown"


def categorise(match: Match) -> str:
    """Return a category string for *match* based on its pattern name."""
    name_lower = match.pattern_name.lower()
    for keyword, category in _CATEGORY_MAP.items():
        if keyword in name_lower:
            return category
    return UNKNOWN_CATEGORY


@dataclass
class CategorisedMatch:
    match: Match
    category: str

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "category": self.category,
        }


def categorise_match(match: Match) -> CategorisedMatch:
    return CategorisedMatch(match=match, category=categorise(match))


def categorise_all(matches: List[Match]) -> List[CategorisedMatch]:
    return [categorise_match(m) for m in matches]


def group_by_category(matches: List[Match]) -> Dict[str, List[Match]]:
    result: Dict[str, List[Match]] = {}
    for m in matches:
        cat = categorise(m)
        result.setdefault(cat, []).append(m)
    return result
