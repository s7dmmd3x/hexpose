"""Pre/post scan hook system for hexpose."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from hexpose.scanner import ScanResult


@dataclass
class HookContext:
    """Shared context passed to every hook in a pipeline run."""

    source: str
    result: Optional[ScanResult] = None
    metadata: dict = field(default_factory=dict)


# Type aliases
PreScanHook = Callable[[HookContext], None]
PostScanHook = Callable[[HookContext], None]


class HookRegistry:
    """Registry that stores and dispatches pre/post scan hooks."""

    def __init__(self) -> None:
        self._pre: List[PreScanHook] = []
        self._post: List[PostScanHook] = []

    # ------------------------------------------------------------------
    # Registration helpers
    # ------------------------------------------------------------------

    def register_pre(self, fn: PreScanHook) -> PreScanHook:
        """Register a pre-scan hook (also usable as a decorator)."""
        self._pre.append(fn)
        return fn

    def register_post(self, fn: PostScanHook) -> PostScanHook:
        """Register a post-scan hook (also usable as a decorator)."""
        self._post.append(fn)
        return fn

    # ------------------------------------------------------------------
    # Dispatch helpers
    # ------------------------------------------------------------------

    def run_pre(self, ctx: HookContext) -> None:
        """Execute all registered pre-scan hooks in order."""
        for hook in self._pre:
            hook(ctx)

    def run_post(self, ctx: HookContext) -> None:
        """Execute all registered post-scan hooks in order."""
        for hook in self._post:
            hook(ctx)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def pre_hooks(self) -> List[PreScanHook]:
        return list(self._pre)

    @property
    def post_hooks(self) -> List[PostScanHook]:
        return list(self._post)

    def clear(self) -> None:
        """Remove all registered hooks (useful in tests)."""
        self._pre.clear()
        self._post.clear()


# Module-level default registry
default_registry = HookRegistry()
