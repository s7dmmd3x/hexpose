"""Built-in regex patterns for detecting common secrets and credentials."""

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern
    severity: str  # "high", "medium", "low"
    description: str


RAW_PATTERNS: List[dict] = [
    {
        "name": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "high",
        "description": "Amazon Web Services access key ID",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s=:]+[A-Za-z0-9/+=]{40}",
        "severity": "high",
        "description": "Amazon Web Services secret access key",
    },
    {
        "name": "Generic API Key",
        "pattern": r"(?i)api[_\-]?key[\s=:]+[A-Za-z0-9_\-]{16,64}",
        "severity": "medium",
        "description": "Generic API key assignment",
    },
    {
        "name": "Bearer Token",
        "pattern": r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        "severity": "high",
        "description": "HTTP Bearer authentication token",
    },
    {
        "name": "Private Key Header",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "high",
        "description": "PEM-encoded private key block",
    },
    {
        "name": "GitHub Token",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "severity": "high",
        "description": "GitHub personal access token",
    },
    {
        "name": "Slack Token",
        "pattern": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
        "severity": "high",
        "description": "Slack API or bot token",
    },
    {
        "name": "Generic Password",
        "pattern": r"(?i)password[\s=:]+[^\s]{8,}",
        "severity": "medium",
        "description": "Plaintext password assignment",
    },
    {
        "name": "Connection String",
        "pattern": r"(?i)(mongodb|postgresql|mysql|redis):\/\/[^\s'\"]{8,}",
        "severity": "high",
        "description": "Database connection string with credentials",
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\9_\-]+",
        "severity": "medium",
        "description": "JSON Web Token (JWT)",
    },
]


def load_patterns() -> List[SecretPattern]:
    """Compile and return all built-in secret patterns."""
    return [
        SecretPattern(
            name=p["name"],
            pattern=re.compile(p["pattern"]),
            severity=p["severity"],
            description=p["description"],
        )
        for p in RAW_PATTERNS
    ]
