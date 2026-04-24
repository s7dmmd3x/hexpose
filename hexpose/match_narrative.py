"""match_narrative.py — attach human-readable narrative summaries to matches."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from hexpose.scanner import Match

_TEMPLATES: dict[str, str] = {
    "aws_access_key": (
        "An AWS Access Key ID was detected. If exposed, an attacker could use "
        "this credential to authenticate against AWS services and potentially "
        "access or exfiltrate cloud resources."
    ),
    "aws_secret_key": (
        "An AWS Secret Access Key was detected. Combined with an Access Key ID "
        "this grants full programmatic access to AWS APIs."
    ),
    "github_token": (
        "A GitHub personal access token was found. This may allow read or write "
        "access to repositories and GitHub API resources."
    ),
    "jwt": (
        "A JSON Web Token (JWT) was identified. Depending on the signing secret "
        "and claims, this token may grant authenticated access to an application."
    ),
    "password": (
        "A plain-text password or password-like value was detected. Exposure of "
        "passwords can lead to account compromise."
    ),
    "generic_secret": (
        "A generic secret or high-entropy string was found. Review the value to "
        "determine whether it represents a credential or cryptographic key."
    ),
}

_DEFAULT_NARRATIVE = (
    "A potential secret or credential was detected. Manual review is recommended "
    "to assess the risk and determine whether the value should be rotated."
)


@dataclass
class NarrativeMatch:
    """A Match decorated with a narrative summary."""

    match: Match
    narrative: str
    recommendations: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "severity": self.match.severity,
            "narrative": self.narrative,
            "recommendations": self.recommendations,
        }

    def __str__(self) -> str:  # pragma: no cover
        return f"[{self.match.pattern_name}] {self.narrative}"


def _lookup_narrative(pattern_name: str) -> str:
    key = pattern_name.lower().replace("-", "_").replace(" ", "_")
    for fragment, text in _TEMPLATES.items():
        if fragment in key:
            return text
    return _DEFAULT_NARRATIVE


def _build_recommendations(match: Match) -> List[str]:
    recs: List[str] = []
    severity = (match.severity or "").lower()
    if severity in ("critical", "high"):
        recs.append("Rotate or revoke this credential immediately.")
    recs.append("Remove the secret from source code and binary artifacts.")
    recs.append("Audit access logs for unauthorised use of this credential.")
    if severity in ("critical", "high", "medium"):
        recs.append("Store secrets in a dedicated secrets manager (e.g. Vault, AWS Secrets Manager).")
    return recs


def attach_narrative(match: Match, narrative: Optional[str] = None) -> NarrativeMatch:
    """Return a NarrativeMatch for *match*, optionally overriding the narrative text."""
    text = narrative if narrative is not None else _lookup_narrative(match.pattern_name)
    recs = _build_recommendations(match)
    return NarrativeMatch(match=match, narrative=text, recommendations=recs)


def attach_narrative_all(
    matches: List[Match],
) -> List[NarrativeMatch]:
    """Attach narratives to every match in *matches*."""
    return [attach_narrative(m) for m in matches]
