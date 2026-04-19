"""Classify matches into broad threat categories with a confidence tier."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from hexpose.scanner import Match

_CATEGORY_RULES: List[tuple] = [
    ("cloud_credential", ["aws", "gcp", "azure", "digitalocean"]),
    ("version_control", ["github", "gitlab", "bitbucket"]),
    ("database", ["postgres", "mysql", "mongo", "redis", "sqlite"]),
    ("auth_token", ["jwt", "oauth", "bearer", "token", "api_key", "apikey"]),
    ("private_key", ["rsa", "pem", "private_key", "ssh", "pgp"]),
    ("password", ["password", "passwd", "secret", "credential"]),
]

_TIER_THRESHOLDS = {
    "definite": 2,
    "probable": 1,
    "possible": 0,
}


def _classify(pattern_name: str) -> str:
    lower = pattern_name.lower()
    for category, keywords in _CATEGORY_RULES:
        if any(kw in lower for kw in keywords):
            return category
    return "generic"


def _tier(match: Match, category: str) -> str:
    score = 0
    if category != "generic":
        score += 1
    severity = (match.severity or "").lower()
    if severity in ("critical", "high"):
        score += 1
    if score >= _TIER_THRESHOLDS["definite"]:
        return "definite"
    if score >= _TIER_THRESHOLDS["probable"]:
        return "probable"
    return "possible"


@dataclass
class ClassifiedMatch:
    match: Match
    category: str
    tier: str
    keywords_matched: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "category": self.category,
            "tier": self.tier,
            "keywords_matched": self.keywords_matched,
            "severity": self.match.severity,
            "offset": self.match.offset,
        }


def classify_match(match: Match) -> ClassifiedMatch:
    lower = match.pattern_name.lower()
    category = "generic"
    matched_kws: List[str] = []
    for cat, keywords in _CATEGORY_RULES:
        hits = [kw for kw in keywords if kw in lower]
        if hits:
            category = cat
            matched_kws = hits
            break
    tier = _tier(match, category)
    return ClassifiedMatch(match=match, category=category, tier=tier, keywords_matched=matched_kws)


def classify_all(matches: List[Match]) -> List[ClassifiedMatch]:
    return [classify_match(m) for m in matches]
