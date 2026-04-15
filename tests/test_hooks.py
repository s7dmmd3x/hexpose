"""Tests for hexpose.hooks and hexpose.hook_builtins."""
from __future__ import annotations

import pytest

from hexpose.hooks import HookContext, HookRegistry
from hexpose.hook_builtins import (
    log_findings_post,
    register_builtins,
    timing_post,
    timing_pre,
)
from hexpose.scanner import Match, ScanResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(n_matches: int = 0) -> ScanResult:
    matches = [
        Match(
            pattern_name="test",
            value="secret",
            offset=0,
            line_number=1,
            severity="high",
            context="",
        )
        for _ in range(n_matches)
    ]
    return ScanResult(source="test", matches=matches)


# ---------------------------------------------------------------------------
# HookRegistry
# ---------------------------------------------------------------------------

class TestHookRegistry:
    def test_register_pre_and_dispatch(self):
        reg = HookRegistry()
        called = []
        reg.register_pre(lambda ctx: called.append("pre"))
        ctx = HookContext(source="x")
        reg.run_pre(ctx)
        assert called == ["pre"]

    def test_register_post_and_dispatch(self):
        reg = HookRegistry()
        called = []
        reg.register_post(lambda ctx: called.append("post"))
        ctx = HookContext(source="x")
        reg.run_post(ctx)
        assert called == ["post"]

    def test_decorator_usage(self):
        reg = HookRegistry()

        @reg.register_pre
        def hook(ctx: HookContext) -> None:
            ctx.metadata["hit"] = True

        ctx = HookContext(source="x")
        reg.run_pre(ctx)
        assert ctx.metadata["hit"] is True

    def test_hooks_run_in_order(self):
        reg = HookRegistry()
        order: list[int] = []
        reg.register_pre(lambda ctx: order.append(1))
        reg.register_pre(lambda ctx: order.append(2))
        reg.run_pre(HookContext(source="x"))
        assert order == [1, 2]

    def test_clear_removes_all_hooks(self):
        reg = HookRegistry()
        reg.register_pre(lambda ctx: None)
        reg.register_post(lambda ctx: None)
        reg.clear()
        assert reg.pre_hooks == []
        assert reg.post_hooks == []

    def test_introspection_properties(self):
        reg = HookRegistry()
        fn = lambda ctx: None  # noqa: E731
        reg.register_pre(fn)
        assert fn in reg.pre_hooks
        assert fn not in reg.post_hooks


# ---------------------------------------------------------------------------
# Built-in hooks
# ---------------------------------------------------------------------------

class TestBuiltinHooks:
    def test_timing_hooks_record_elapsed(self):
        ctx = HookContext(source="x")
        timing_pre(ctx)
        timing_post(ctx)
        assert "elapsed_seconds" in ctx.metadata
        assert ctx.metadata["elapsed_seconds"] >= 0

    def test_timing_post_without_pre_is_safe(self):
        ctx = HookContext(source="x")
        timing_post(ctx)  # should not raise
        assert "elapsed_seconds" not in ctx.metadata

    def test_log_findings_post_no_result(self, caplog):
        ctx = HookContext(source="x")
        log_findings_post(ctx)  # should not raise

    def test_log_findings_post_with_findings(self, caplog):
        import logging
        ctx = HookContext(source="firmware.bin", result=_make_result(2))
        with caplog.at_level(logging.WARNING, logger="hexpose.hook_builtins"):
            log_findings_post(ctx)
        assert "2 finding(s)" in caplog.text

    def test_register_builtins_adds_hooks(self):
        reg = HookRegistry()
        register_builtins(reg)
        assert len(reg.pre_hooks) >= 1
        assert len(reg.post_hooks) >= 2
