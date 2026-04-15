"""Registry that merges built-in patterns with plugin-supplied patterns."""

from typing import List, Optional

from hexpose.patterns import SecretPattern, load_patterns
from hexpose.plugin import load_plugins


class PatternRegistry:
    """Holds all active SecretPattern instances for a scan session."""

    def __init__(
        self,
        plugin_paths: Optional[List[str]] = None,
        include_builtin: bool = True,
    ) -> None:
        self._patterns: List[SecretPattern] = []

        if include_builtin:
            self._patterns.extend(load_patterns())

        if plugin_paths:
            self._patterns.extend(load_plugins(plugin_paths))

    @property
    def patterns(self) -> List[SecretPattern]:
        """Return all registered patterns (built-in + plugins)."""
        return list(self._patterns)

    def add(self, pattern: SecretPattern) -> None:
        """Manually register an additional pattern."""
        self._patterns.append(pattern)

    def names(self) -> List[str]:
        """Return the names of all registered patterns."""
        return [p.name for p in self._patterns]

    def __len__(self) -> int:
        return len(self._patterns)

    def __repr__(self) -> str:  # pragma: no cover
        return f"PatternRegistry(count={len(self._patterns)})"
