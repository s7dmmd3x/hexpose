"""Built-in hooks shipped with hexpose."""
from __future__ import annotations

import logging
import time

from hexpose.hooks import HookContext, HookRegistry

logger = logging.getLogger(__name__)


def timing_pre(ctx: HookContext) -> None:
    """Record scan start time in context metadata."""
    ctx.metadata["_start_time"] = time.monotonic()


def timing_post(ctx: HookContext) -> None:
    """Compute and store elapsed scan time in context metadata."""
    start = ctx.metadata.get("_start_time")
    if start is not None:
        ctx.metadata["elapsed_seconds"] = round(time.monotonic() - start, 4)


def log_findings_post(ctx: HookContext) -> None:
    """Log a summary of findings after a scan completes."""
    if ctx.result is None:
        return
    count = len(ctx.result.matches)
    level = logging.WARNING if count else logging.INFO
    logger.log(level, "[hexpose] %s — %d finding(s)", ctx.source, count)


def register_builtins(registry: HookRegistry) -> None:
    """Register all built-in hooks onto *registry*."""
    registry.register_pre(timing_pre)
    registry.register_post(timing_post)
    registry.register_post(log_findings_post)
