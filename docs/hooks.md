# Scan Hooks

Hexpose exposes a lightweight **hook system** that lets you run custom logic
before and after every scan without modifying core code.

## Concepts

| Term | Description |
|------|-------------|
| `HookContext` | Shared object passed to every hook; carries `source`, `result`, and a free-form `metadata` dict. |
| `PreScanHook` | Called **before** the scanner processes bytes. |
| `PostScanHook` | Called **after** the scanner returns a `ScanResult`. |
| `HookRegistry` | Container that stores hooks and dispatches them in registration order. |

## Quick Start

```python
from hexpose.hooks import default_registry, HookContext

@default_registry.register_post
def my_hook(ctx: HookContext) -> None:
    if ctx.result and ctx.result.matches:
        print(f"Alert: {len(ctx.result.matches)} secrets found in {ctx.source}")
```

## Built-in Hooks

Register the built-in timing and logging hooks:

```python
from hexpose.hook_builtins import register_builtins
from hexpose.hooks import HookRegistry

registry = HookRegistry()
register_builtins(registry)
```

Built-in hooks provided:

- **`timing_pre`** / **`timing_post`** — measure scan wall-clock time; stored in `ctx.metadata["elapsed_seconds"]`.
- **`log_findings_post`** — emit a `WARNING` log when secrets are found, `INFO` otherwise.

## Integration with the Scanner

Pass the registry to your scan loop:

```python
from hexpose.hooks import HookContext, default_registry
from hexpose.scanner import Scanner

scanner = Scanner()
ctx = HookContext(source="firmware.bin")
default_registry.run_pre(ctx)
ctx.result = scanner.scan_bytes(data, source="firmware.bin")
default_registry.run_post(ctx)
```

## Writing a Plugin Hook

Plugins can register hooks during their `get_patterns()` call or as a
separate entry point. See `docs/plugins.md` for details.
