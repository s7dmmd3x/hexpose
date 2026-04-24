"""match_cohort.py — group matches into cohorts based on shared attributes.

A *cohort* is a named collection of matches that share a common property
(e.g. the same pattern family, severity tier, or custom tag).  Cohorts
make it easy to reason about clusters of related findings across multiple
scan results without the heavyweight machinery of full clustering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

from hexpose.scanner import Match

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class CohortMatch:
    """A :class:`Match` decorated with its assigned cohort name."""

    match: Match
    cohort: str

    def as_dict(self) -> dict:
        """Return a JSON-serialisable representation."""
        return {
            "cohort": self.cohort,
            "pattern_name": self.match.pattern_name,
            "value": self.match.value,
            "offset": self.match.offset,
            "severity": self.match.severity,
        }

    def __str__(self) -> str:
        return f"[{self.cohort}] {self.match.pattern_name} @ {self.match.offset}"


@dataclass
class Cohort:
    """A named group of :class:`CohortMatch` instances."""

    name: str
    members: List[CohortMatch] = field(default_factory=list)

    def add(self, cm: CohortMatch) -> None:
        """Append *cm* to this cohort."""
        self.members.append(cm)

    @property
    def size(self) -> int:
        """Number of members in this cohort."""
        return len(self.members)

    def as_dict(self) -> dict:
        """Return a JSON-serialisable representation."""
        return {
            "name": self.name,
            "size": self.size,
            "members": [m.as_dict() for m in self.members],
        }


@dataclass
class CohortReport:
    """Collection of all cohorts produced by :func:`build_cohorts`."""

    cohorts: Dict[str, Cohort] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.cohorts)

    def names(self) -> List[str]:
        """Sorted list of cohort names."""
        return sorted(self.cohorts.keys())

    def get(self, name: str) -> Optional[Cohort]:
        """Return the :class:`Cohort` for *name*, or ``None``."""
        return self.cohorts.get(name)

    def as_dict(self) -> dict:
        """Return a JSON-serialisable representation."""
        return {name: cohort.as_dict() for name, cohort in self.cohorts.items()}


# ---------------------------------------------------------------------------
# Built-in key functions
# ---------------------------------------------------------------------------


def _key_severity(match: Match) -> str:
    """Group by severity string (normalised to lower-case)."""
    return (match.severity or "unknown").lower()


def _key_pattern_prefix(match: Match) -> str:
    """Group by the first token of the pattern name (before the first '_')."""
    name = match.pattern_name or "unknown"
    return name.split("_")[0].lower()


def _key_value_length_bucket(match: Match) -> str:
    """Coarse bucket based on secret length: short / medium / long."""
    n = len(match.value or "")
    if n < 16:
        return "short"
    if n < 40:
        return "medium"
    return "long"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_cohorts(
    matches: Iterable[Match],
    key: Callable[[Match], str] = _key_severity,
) -> CohortReport:
    """Partition *matches* into cohorts using *key*.

    Parameters
    ----------
    matches:
        Any iterable of :class:`~hexpose.scanner.Match` objects.
    key:
        Callable that maps a :class:`Match` to a cohort name string.
        Defaults to :func:`_key_severity`.

    Returns
    -------
    CohortReport
        A :class:`CohortReport` whose ``cohorts`` dict is keyed by the
        strings returned by *key*.
    """
    report = CohortReport()
    for match in matches:
        cohort_name = key(match)
        if cohort_name not in report.cohorts:
            report.cohorts[cohort_name] = Cohort(name=cohort_name)
        cm = CohortMatch(match=match, cohort=cohort_name)
        report.cohorts[cohort_name].add(cm)
    return report
