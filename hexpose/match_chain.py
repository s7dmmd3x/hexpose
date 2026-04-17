"""match_chain.py — pipeline chaining for match transformations."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, List
from hexpose.scanner import Match

Transform = Callable[[Match], Match | None]


@dataclass
class MatchChain:
    """Ordered sequence of transform functions applied to each Match."""
    _steps: List[Transform] = field(default_factory=list)

    def add(self, fn: Transform) -> "MatchChain":
        """Append a transform step and return self for chaining."""
        self._steps.append(fn)
        return self

    def run(self, match: Match) -> Match | None:
        """Apply every step in order; return None if any step drops the match."""
        current: Match | None = match
        for step in self._steps:
            if current is None:
                return None
            current = step(current)
        return current

    def run_all(self, matches: List[Match]) -> List[Match]:
        """Apply the chain to a list, dropping None results."""
        results = []
        for m in matches:
            out = self.run(m)
            if out is not None:
                results.append(out)
        return results

    def __len__(self) -> int:
        return len(self._steps)


def build_chain(*fns: Transform) -> MatchChain:
    """Convenience factory — build a MatchChain from positional callables."""
    chain = MatchChain()
    for fn in fns:
        chain.add(fn)
    return chain
