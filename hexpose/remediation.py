"""Remediation hints for detected secrets."""
from dataclasses import dataclass
from typing import Optional
from hexpose.scanner import Match


@dataclass
class RemediationHint:
    pattern_name: str
    summary: str
    steps: list[str]
    reference: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.pattern_name,
            "summary": self.summary,
            "steps": self.steps,
            "reference": self.reference,
        }


_HINTS: dict[str, RemediationHint] = {
    "aws_access_key": RemediationHint(
        pattern_name="aws_access_key",
        summary="Rotate the exposed AWS access key immediately.",
        steps=[
            "Go to AWS IAM console and deactivate the key.",
            "Generate a new key pair and update all consumers.",
            "Review CloudTrail logs for unauthorized usage.",
            "Remove the key from source code and history.",
        ],
        reference="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    ),
    "github_token": RemediationHint(
        pattern_name="github_token",
        summary="Revoke the exposed GitHub token immediately.",
        steps=[
            "Navigate to GitHub Settings > Developer settings > Personal access tokens.",
            "Revoke the token and create a replacement with minimal scopes.",
            "Audit recent API activity for the token.",
        ],
        reference="https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation",
    ),
    "generic_secret": RemediationHint(
        pattern_name="generic_secret",
        summary="Rotate or invalidate the exposed secret.",
        steps=[
            "Identify the service this secret belongs to.",
            "Rotate or revoke the credential via that service's console.",
            "Update all references to use the new credential.",
            "Store secrets in a vault or environment variable, not in code.",
        ],
    ),
}

_DEFAULT_HINT = RemediationHint(
    pattern_name="unknown",
    summary="Rotate or invalidate any exposed credential.",
    steps=[
        "Identify what system the secret grants access to.",
        "Revoke or rotate the credential immediately.",
        "Audit access logs for misuse.",
        "Use a secrets manager to avoid future exposure.",
    ],
)


def get_hint(pattern_name: str) -> RemediationHint:
    """Return a remediation hint for the given pattern name."""
    return _HINTS.get(pattern_name, _DEFAULT_HINT)


def annotate_match(match: Match) -> dict:
    """Return match info merged with its remediation hint."""
    hint = get_hint(match.pattern_name)
    return {"match": match, "remediation": hint.as_dict()}
