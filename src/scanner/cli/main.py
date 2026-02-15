"""Command-line interface for the secrets scanner.

Provides the main CLI entry point with the following commands:
- scan: Scan files/directories for secrets
- install-hook: Install pre-commit hook
- init: Create a .secretsignore file
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scanner import __version__
from scanner.core import SecretScanner
from scanner.models import ScanConfig, ScanResult, Severity
from scanner.patterns import create_default_registry
from scanner.reports import generate_report
from scanner.utils.config import load_config, merge_cli_args
from scanner.utils.git import scan_git_history

console = Console()
error_console = Console(stderr=True)

# Exit codes
EXIT_CLEAN = 0
EXIT_SECRETS_FOUND = 1
EXIT_ERROR = 2


def _print_banner() -> None:
    """Print the application banner."""
    banner = Text()
    banner.append("🔍 ", style="bold")
    banner.append("Dotenv Secrets Scanner", style="bold cyan")
    banner.append(f" v{__version__}", style="dim")
    console.print(banner)
    console.print()


def _print_findings(result: ScanResult) -> None:
    """Print findings to the console using Rich formatting."""
    severity_styles = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
    }

    severity_icons = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
    }

    for finding in result.findings:
        style = severity_styles.get(finding.severity, "white")
        icon = severity_icons.get(finding.severity, "⚪")

        # Finding header
        header = Text()
        header.append(f"{icon} {finding.severity.name}", style=style)
        header.append(f": {finding.pattern_name}", style="bold white")

        panel_content = Text()
        panel_content.append(f"File: ", style="dim")
        panel_content.append(f"{finding.file_path}", style="bold")
        panel_content.append(f":{finding.line_number}\n", style="bold")
        panel_content.append(f"Secret: ", style="dim")
        panel_content.append(f"{finding.masked_secret}\n", style="red")
        panel_content.append(f"Confidence: ", style="dim")
        panel_content.append(f"{finding.confidence:.0%}\n", style="white")

        # Context
        if finding.context_before or finding.context_after:
            panel_content.append("\n")
            start_num = finding.line_number - len(finding.context_before)
            for i, line in enumerate(finding.context_before):
                num = start_num + i
                panel_content.append(f"  {num:>4} │ {line}\n", style="dim")
            panel_content.append(
                f"  {finding.line_number:>4} │ {finding.line_content}\n", style="bold red"
            )
            for i, line in enumerate(finding.context_after):
                num = finding.line_number + 1 + i
                panel_content.append(f"  {num:>4} │ {line}\n", style="dim")

        if finding.recommendation:
            panel_content.append(f"\n💡 ", style="bold")
            panel_content.append(finding.recommendation, style="italic cyan")

        console.print(Panel(panel_content, title=str(header), border_style=style, expand=True))


def _print_summary(result: ScanResult) -> None:
    """Print scan summary table."""
    console.print()

    # Stats table
    table = Table(title="📊 Scan Results", show_header=False, border_style="dim")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Files scanned", str(result.files_scanned))
    table.add_row("Files skipped", str(result.files_skipped))
    table.add_row("Duration", f"{result.duration_seconds:.2f}s")
    table.add_row("Total findings", str(len(result.findings)))

    counts = result.severity_counts()
    if counts["CRITICAL"] > 0:
        table.add_row("  CRITICAL", f"[bold red]{counts['CRITICAL']}[/]")
    if counts["HIGH"] > 0:
        table.add_row("  HIGH", f"[bold yellow]{counts['HIGH']}[/]")
    if counts["MEDIUM"] > 0:
        table.add_row("  MEDIUM", f"[yellow]{counts['MEDIUM']}[/]")
    if counts["LOW"] > 0:
        table.add_row("  LOW", f"[cyan]{counts['LOW']}[/]")

    console.print(table)

    if result.errors:
        console.print(f"\n[dim]⚠️  {len(result.errors)} error(s) occurred during scanning.[/]")

    if result.has_secrets:
        if result.critical_count > 0:
            console.print("\n[bold red]🚨 Action required: Critical secrets must be rotated![/]")
        console.print()
    else:
        console.print("\n[bold green]✅ No secrets detected. Repository is clean.[/]\n")


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version=__version__, prog_name="secrets-scan")
def cli(ctx: click.Context) -> None:
    """🔍 Dotenv Secrets Scanner — Detect secrets in your code.

    Scans files, directories, and Git history for accidentally committed
    secrets like API keys, passwords, and tokens.

    \b
    Quick Start:
        secrets-scan scan .
        secrets-scan scan --severity HIGH
        secrets-scan scan --output json > report.json
        secrets-scan install-hook
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--severity", "-s",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default=None,
    help="Minimum severity level to report.",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["console", "json", "text", "html", "sarif"], case_sensitive=False),
    default="console",
    help="Output format.",
)
@click.option(
    "--output-file", "-f",
    type=click.Path(),
    default=None,
    help="Write report to a file.",
)
@click.option(
    "--git-history", "-g",
    is_flag=True,
    default=False,
    help="Scan Git commit history.",
)
@click.option(
    "--max-commits",
    type=int,
    default=50,
    help="Max commits to scan in git history mode.",
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to configuration file (.secretscan.yml).",
)
@click.option(
    "--max-file-size",
    type=int,
    default=None,
    help="Max file size in bytes to scan.",
)
@click.option(
    "--exclude", "-e",
    multiple=True,
    help="Additional directories to exclude.",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable colored output.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose logging.",
)
@click.option(
    "--fail-on-severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default="LOW",
    help="Minimum severity level that will cause a non-zero exit code.",
)
@click.option(
    "--context-lines",
    type=int,
    default=None,
    help="Override number of context lines around findings.",
)
@click.option(
    "--workers",
    type=int,
    default=None,
    help="Maximum number of worker threads for scanning.",
)
@click.option(
    "--baseline",
    type=click.Path(exists=True),
    default=None,
    help="Path to a baseline file to suppress known findings.",
)
@click.option(
    "--write-baseline",
    type=click.Path(),
    default=None,
    help="Write current findings to a baseline file.",
)
def scan(
    path: str,
    severity: str | None,
    output: str,
    output_file: str | None,
    git_history: bool,
    max_commits: int,
    config: str | None,
    max_file_size: int | None,
    exclude: tuple[str, ...],
    no_color: bool,
    verbose: bool,
    fail_on_severity: str,
    context_lines: int | None,
    workers: int | None,
    baseline: str | None,
    write_baseline: str | None,
) -> None:
    """Scan files and directories for secrets.

    \b
    Examples:
        secrets-scan scan .
        secrets-scan scan /path/to/project --severity HIGH
        secrets-scan scan . --output json --output-file report.json
        secrets-scan scan . --git-history --max-commits 100
    """
    import logging

    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    scan_path = Path(path).resolve()

    if no_color:
        console.no_color = True

    # Load configuration
    config_path = Path(config) if config else None
    scan_config = load_config(
        config_path=config_path,
        scan_dir=scan_path if scan_path.is_dir() else scan_path.parent,
    )
    scan_config = merge_cli_args(
        scan_config,
        severity=severity,
        max_file_size=max_file_size,
        exclude=list(exclude) if exclude else None,
        context_lines=context_lines,
        workers=workers,
    )

    if output == "console":
        _print_banner()
        console.print(f"[dim]Scanning:[/] {scan_path}")
        console.print()

    # Perform scan
    scanner = SecretScanner(config=scan_config)

    if git_history:
        # Git history scanning
        if output == "console":
            with console.status("[bold cyan]Scanning git history..."):
                findings = scan_git_history(
                    repo_path=scan_path,
                    max_commits=max_commits,
                    config=scan_config,
                )
        else:
            findings = scan_git_history(
                repo_path=scan_path,
                max_commits=max_commits,
                config=scan_config,
            )

        result = ScanResult(
            findings=findings,
            files_scanned=max_commits,
            scan_path=str(scan_path),
        )
    else:
        # File/directory scanning
        if scan_path.is_file():
            findings = scanner.scan_file(scan_path)
            result = ScanResult(
                findings=findings,
                files_scanned=1,
                scan_path=str(scan_path),
            )
        else:
            if output == "console":
                with console.status("[bold cyan]Scanning files..."):
                    result = scanner.scan_directory(scan_path)
            else:
                result = scanner.scan_directory(scan_path)

    # Baseline handling
    original_result = result
    if write_baseline:
        baseline_path = Path(write_baseline)
        baseline_data: dict[str, Any] = {
            "version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": [
                {
                    "pattern_id": f.pattern_id,
                    "file_path": str(f.file_path),
                    "line_number": f.line_number,
                    "masked_secret": f.masked_secret,
                }
                for f in original_result.findings
            ],
        }
        baseline_path.write_text(json.dumps(baseline_data, indent=2), encoding="utf-8")

    if baseline:
        baseline_path = Path(baseline)
        try:
            raw = baseline_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            entries = data.get("entries", [])
            baseline_keys = {
                (
                    str(e.get("file_path", "")),
                    int(e.get("line_number", 0)),
                    str(e.get("pattern_id", "")),
                    str(e.get("masked_secret", "")),
                )
                for e in entries
            }
            filtered_findings = [
                f
                for f in result.findings
                if (
                    str(f.file_path),
                    f.line_number,
                    f.pattern_id,
                    f.masked_secret,
                )
                not in baseline_keys
            ]
            result = ScanResult(
                findings=filtered_findings,
                files_scanned=original_result.files_scanned,
                files_skipped=original_result.files_skipped,
                duration_seconds=original_result.duration_seconds,
                scan_path=original_result.scan_path,
                errors=original_result.errors,
            )
        except Exception as exc:  # pragma: no cover - defensive
            error_console.print(f"[bold red]Failed to load baseline:[/] {exc}")

    # Output
    if output == "console":
        if result.findings:
            _print_findings(result)
        _print_summary(result)
    else:
        output_path = Path(output_file) if output_file else None
        report = generate_report(result, format=output, output_path=output_path)
        if not output_file:
            click.echo(report)

    # Exit code
    exit_code = EXIT_CLEAN
    if result.findings:
        highest = max((f.severity for f in result.findings), default=None)
        threshold = Severity.from_string(fail_on_severity)
        if highest is not None and highest >= threshold:
            exit_code = EXIT_SECRETS_FOUND

    sys.exit(exit_code)


@cli.command("install-hook")
@click.option(
    "--repo", "-r",
    type=click.Path(exists=True),
    default=".",
    help="Path to the Git repository.",
)
def install_hook(repo: str) -> None:
    """Install pre-commit hook to scan staged files.

    \b
    The hook will automatically scan staged files before each commit
    and block the commit if secrets are detected.
    """
    from scanner.hooks.pre_commit import install_hook as do_install

    try:
        hook_path = do_install(Path(repo).resolve())
        console.print(f"[bold green]✅ Pre-commit hook installed:[/] {hook_path}")
        console.print("[dim]Staged files will be scanned before each commit.[/]")
        console.print("[dim]Bypass with: git commit --no-verify[/]")
    except FileNotFoundError as exc:
        error_console.print(f"[bold red]❌ Error:[/] {exc}")
        sys.exit(EXIT_ERROR)


@cli.command("uninstall-hook")
@click.option(
    "--repo", "-r",
    type=click.Path(exists=True),
    default=".",
    help="Path to the Git repository.",
)
def uninstall_hook(repo: str) -> None:
    """Uninstall the pre-commit hook."""
    from scanner.hooks.pre_commit import uninstall_hook as do_uninstall

    try:
        removed = do_uninstall(Path(repo).resolve())
        if removed:
            console.print("[bold green]✅ Pre-commit hook removed.[/]")
        else:
            console.print("[yellow]ℹ️  No secrets-scanner hook found.[/]")
    except FileNotFoundError as exc:
        error_console.print(f"[bold red]❌ Error:[/] {exc}")
        sys.exit(EXIT_ERROR)


@cli.command()
@click.option(
    "--path", "-p",
    type=click.Path(),
    default=".",
    help="Directory to create .secretsignore in.",
)
def init(path: str) -> None:
    """Create a .secretsignore file with default patterns.

    \b
    The .secretsignore file works like .gitignore but for
    suppressing known false positives.
    """
    target = Path(path).resolve() / ".secretsignore"

    if target.exists():
        if not click.confirm(f".secretsignore already exists at {target}. Overwrite?"):
            console.print("[dim]Aborted.[/]")
            return

    content = """\
# .secretsignore - Suppress known false positives
# Format: file glob pattern, one per line
# Lines starting with # are comments

# Example: ignore all test files
# tests/**

# Example: ignore specific file and line
# config/settings.py:15

# Ignore example/sample files
*.example
*.sample
*.template
*.dist
"""
    target.write_text(content, encoding="utf-8")
    console.print(f"[bold green]✅ Created:[/] {target}")
    console.print("[dim]Edit this file to suppress known false positives.[/]")


@cli.command("patterns")
@click.option(
    "--severity", "-s",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default=None,
    help="Minimum severity level to include.",
)
def list_patterns(severity: str | None) -> None:
    """List built-in detection patterns."""
    registry = create_default_registry()
    patterns = list(registry)

    min_severity = Severity.from_string(severity) if severity else None
    if min_severity is not None:
        patterns = [p for p in patterns if p.severity >= min_severity]

    table = Table(title="Built-in Secret Patterns")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("Severity", style="magenta")
    table.add_column("Description", style="dim")

    for pattern in sorted(patterns, key=lambda p: (p.severity.value * -1, p.id)):
        table.add_row(
            pattern.id,
            pattern.name,
            pattern.severity.name,
            pattern.description,
        )

    console.print(table)


if __name__ == "__main__":
    cli()
