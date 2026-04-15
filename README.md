# hexpose

> CLI tool for scanning binaries and memory dumps for embedded secrets and credentials

---

## Installation

```bash
pip install hexpose
```

Or install from source:

```bash
git clone https://github.com/youruser/hexpose.git && cd hexpose && pip install .
```

---

## Usage

Scan a binary or memory dump for embedded secrets:

```bash
hexpose scan ./target_binary
```

Scan a memory dump with verbose output:

```bash
hexpose scan ./memdump.raw --verbose
```

Export findings to JSON:

```bash
hexpose scan ./firmware.bin --output results.json
```

**Example output:**

```
[!] AWS Access Key found at offset 0x3A2F1
[!] Private key header detected at offset 0x7C840
[+] Scan complete: 2 secrets found in firmware.bin
```

### Options

| Flag | Description |
|------|-------------|
| `--verbose` | Show detailed match context |
| `--output FILE` | Export results to a JSON file |
| `--pattern FILE` | Use a custom pattern definition file |

---

## License

This project is licensed under the [MIT License](LICENSE).