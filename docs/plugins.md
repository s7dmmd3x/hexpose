# hexpose Plugin System

hexpose supports **custom pattern plugins** so you can extend the built-in
secret detection rules without modifying the core package.

## Writing a Plugin

A plugin is a plain Python file that exposes a single function:

```python
# my_patterns.py
import re
from hexpose.patterns import SecretPattern

def get_patterns() -> list[SecretPattern]:
    return [
        SecretPattern(
            name="internal_api_key",
            pattern=re.compile(rb"ACME-[A-Z0-9]{32}"),
            severity="high",
            description="ACME internal API key.",
        ),
    ]
```

### SecretPattern fields

| Field         | Type              | Description                              |
|---------------|-------------------|------------------------------------------|
| `name`        | `str`             | Unique identifier for the pattern.       |
| `pattern`     | `re.Pattern[bytes]` | Compiled **bytes** regular expression. |
| `severity`    | `str`             | One of `low`, `medium`, `high`, `critical`. |
| `description` | `str`             | Human-readable description.              |

## Using Plugins via the CLI

Pass one or more plugin files with `--plugin`:

```bash
hexpose scan firmware.bin --plugin my_patterns.py --plugin team_patterns.py
```

## Using Plugins Programmatically

```python
from hexpose.plugin_registry import PatternRegistry
from hexpose.scanner import Scanner

registry = PatternRegistry(plugin_paths=["my_patterns.py"])
scanner = Scanner(patterns=registry.patterns)
result = scanner.scan_file("firmware.bin")
```

## Disabling Built-in Patterns

If you want *only* your custom patterns:

```python
registry = PatternRegistry(plugin_paths=["my_patterns.py"], include_builtin=False)
```

## Error Handling

If a plugin file is missing or does not expose `get_patterns`, hexpose raises
`hexpose.plugin.PluginError` with a descriptive message.
