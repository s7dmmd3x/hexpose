"""Attach environment context (env name, region, team) to matches."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from hexpose.scanner import Match, ScanResult


@dataclass
class EnvironmentMatch:
    match: Match
    env_name: str = "unknown"
    region: Optional[str] = None
    team: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "pattern_name": self.match.pattern_name,
            "offset": self.match.offset,
            "value": self.match.value,
            "severity": self.match.severity,
            "env_name": self.env_name,
            "region": self.region,
            "team": self.team,
            "tags": list(self.tags),
        }

    def __str__(self) -> str:
        parts = [f"[{self.env_name}]"]
        if self.region:
            parts.append(self.region)
        if self.team:
            parts.append(f"team:{self.team}")
        return " ".join(parts) + f" {self.match.pattern_name}"


def attach_environment(
    match: Match,
    env_name: str = "unknown",
    region: Optional[str] = None,
    team: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> EnvironmentMatch:
    """Wrap a single Match with environment metadata."""
    return EnvironmentMatch(
        match=match,
        env_name=env_name,
        region=region,
        team=team,
        tags=list(tags) if tags else [],
    )


def attach_environment_all(
    result: ScanResult,
    env_name: str = "unknown",
    region: Optional[str] = None,
    team: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> List[EnvironmentMatch]:
    """Attach environment metadata to every match in a ScanResult."""
    return [
        attach_environment(m, env_name=env_name, region=region, team=team, tags=tags)
        for m in result.matches
    ]
