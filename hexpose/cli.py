"""Command-line interface for hexpose."""

import sys
from pathlib import Path

import click

from hexpose import __version__
from hexpose.scanner import Scanner

SEVERITY_COLORS = {
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}


@click.command()
@click.version_option(__version__, prog_name="hexpose")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--severity",
    "-s",
    default="low",
    type=click.Choice(["high", "medium", "low"]),
    show_default=True,
    help="Minimum severity level to report.",
)
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output.")
def main(targets, severity: str, no_color: bool) -> None:
    """Scan binary files and memory dumps for embedded secrets."""
    severity_rank = {"low": 0, "medium": 1, "high": 2}
    min_rank = severity_rank[severity]

    scanner = Scanner()
    total_findings = 0
    exit_code = 0

    for target in targets:
        path = Path(target)
        click.echo(f"\nScanning: {path}")
        try:
            result = scanner.scan_file(path)
        except IOError as exc:
            click.secho(f"  ERROR: {exc}", fg="red" if not no_color else None, err=True)
            exit_code = 2
            continue

        filtered = [
            m for m in result.matches if severity_rank[m.severity] >= min_rank
        ]

        if not filtered:
            click.echo("  No findings.")
            continue

        for match in sorted(filtered, key=lambda m: m.offset):
            color = SEVERITY_COLORS.get(match.severity) if not no_color else None
            label = click.style(f"[{match.severity.upper()}]", fg=color, bold=True)
            click.echo(
                f"  {label} {match.pattern_name} "
                f"@ line {match.line_number} (offset {match.offset})"
            )
            click.echo(f"         {match.value!r}")
            total_findings += 1

    click.echo(f"\nTotal findings: {total_findings}")
    sys.exit(exit_code if exit_code else (1 if total_findings else 0))


if __name__ == "__main__":
    main()
