"""Integration test: hooks fire around a real Scanner.scan_bytes call."""
from __future__ import annotations

from hexpose.hooks import HookContext, HookRegistry
from hexpose.hook_builtins import register_builtins
from hexpose.scanner import Scanner


AWS_KEY = b"AKIAIOSFODNN7EXAMPLE"


def _run_scan(data: bytes, registry: HookRegistry) -> HookContext:
    scanner = Scanner()
    ctx = HookContext(source="test_blob")
    registry.run_pre(ctx)
    ctx.result = scanner.scan_bytes(data, source="test_blob")
    registry.run_post(ctx)
    return ctx


class TestHookIntegration:
    def test_timing_metadata_populated(self):
        reg = HookRegistry()
        register_builtins(reg)
        ctx = _run_scan(b"no secrets here", reg)
        assert "elapsed_seconds" in ctx.metadata

    def test_result_available_in_post_hook(self):
        results_seen = []

        reg = HookRegistry()
        reg.register_post(lambda ctx: results_seen.append(ctx.result))

        _run_scan(b"nothing", reg)

        assert len(results_seen) == 1
        assert results_seen[0] is not None

    def test_pre_hook_can_annotate_metadata(self):
        reg = HookRegistry()

        def tag_pre(ctx: HookContext) -> None:
            ctx.metadata["env"] = "ci"

        reg.register_pre(tag_pre)
        ctx = _run_scan(b"nothing", reg)
        assert ctx.metadata["env"] == "ci"

    def test_findings_detected_and_available_in_hook(self):
        findings_count = []

        reg = HookRegistry()
        reg.register_post(
            lambda ctx: findings_count.append(
                len(ctx.result.matches) if ctx.result else 0
            )
        )

        _run_scan(AWS_KEY, reg)

        assert findings_count[0] >= 1
