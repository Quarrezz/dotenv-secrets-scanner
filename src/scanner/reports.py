"""Report generation for scan results.

Supports multiple output formats: console (Rich), JSON, plain text, and HTML.
All formatters implement a common interface for extensibility.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from pathlib import Path

from scanner import __version__
from scanner.models import Finding, ScanResult, Severity


class ReportGenerator(ABC):
    """Abstract base class for report generators."""

    @abstractmethod
    def generate(self, result: ScanResult, output: TextIO | None = None) -> str:
        """Generate a report from scan results.

        Args:
            result: The scan results to report on.
            output: Optional file-like object to write to.

        Returns:
            The report as a string.
        """
        ...


class JSONReportGenerator(ReportGenerator):
    """Generates machine-readable JSON reports."""

    def generate(self, result: ScanResult, output: TextIO | None = None) -> str:
        """Generate JSON report.

        Args:
            result: Scan results.
            output: Optional output stream.

        Returns:
            JSON string.
        """
        report_data = {
            "tool": "dotenv-secrets-scanner",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **result.to_dict(),
        }
        json_str = json.dumps(report_data, indent=2, ensure_ascii=False)

        if output:
            output.write(json_str)

        return json_str


class TextReportGenerator(ReportGenerator):
    """Generates plain text reports for file output or piping."""

    def generate(self, result: ScanResult, output: TextIO | None = None) -> str:
        """Generate plain text report.

        Args:
            result: Scan results.
            output: Optional output stream.

        Returns:
            Plain text report.
        """
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("DOTENV SECRETS SCANNER - SCAN REPORT")
        lines.append("=" * 60)
        lines.append(f"Scan Path: {result.scan_path}")
        lines.append(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Files Scanned: {result.files_scanned}")
        lines.append(f"Files Skipped: {result.files_skipped}")
        lines.append(f"Duration: {result.duration_seconds:.2f}s")
        lines.append("")

        if not result.findings:
            lines.append("No secrets detected. Repository is clean.")
        else:
            lines.append(f"FINDINGS: {len(result.findings)}")
            counts = result.severity_counts()
            for sev_name, count in counts.items():
                if count > 0:
                    lines.append(f"  {sev_name}: {count}")
            lines.append("")
            lines.append("-" * 60)

            for i, finding in enumerate(result.findings, 1):
                lines.append(f"\n[{i}] {finding.severity.name}: {finding.pattern_name}")
                lines.append(f"    File: {finding.file_path}:{finding.line_number}")
                lines.append(f"    Secret: {finding.masked_secret}")
                lines.append(f"    Confidence: {finding.confidence:.0%}")
                if finding.recommendation:
                    lines.append(f"    Recommendation: {finding.recommendation}")
                lines.append("-" * 60)

        if result.errors:
            lines.append(f"\nErrors ({len(result.errors)}):")
            for error in result.errors:
                lines.append(f"  - {error}")

        text = "\n".join(lines)

        if output:
            output.write(text)

        return text


class HTMLReportGenerator(ReportGenerator):
    """Generates styled HTML reports for browser viewing."""

    def generate(self, result: ScanResult, output: TextIO | None = None) -> str:
        """Generate HTML report.

        Args:
            result: Scan results.
            output: Optional output stream.

        Returns:
            HTML string.
        """
        severity_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#17a2b8",
        }

        findings_html = ""
        for finding in result.findings:
            color = severity_colors.get(finding.severity.name, "#6c757d")
            context_html = self._render_context(finding)
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="badge" style="background-color: {color};">
                        {finding.severity.name}
                    </span>
                    <strong>{finding.pattern_name}</strong>
                    <span class="confidence">{finding.confidence:.0%} confidence</span>
                </div>
                <div class="finding-details">
                    <p><strong>File:</strong> {finding.file_path}:{finding.line_number}</p>
                    <p><strong>Secret:</strong> <code>{finding.masked_secret}</code></p>
                    {context_html}
                    <p class="recommendation">💡 {finding.recommendation}</p>
                </div>
            </div>
            """

        counts = result.severity_counts()
        status_class = "success" if not result.has_secrets else "danger"
        status_class = "success" if not result.has_secrets else "danger"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secrets Scanner Report</title>
    <style>
        :root {{
            --bg: #0d1117; --fg: #c9d1d9; --card: #161b22;
            --border: #30363d; --accent: #58a6ff;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg); color: var(--fg); padding: 2rem;
            line-height: 1.6;
        }}
        .container {{ max-width: 960px; margin: 0 auto; }}
        h1 {{ color: var(--accent); margin-bottom: 0.5rem; }}
        .subtitle {{ color: #8b949e; margin-bottom: 2rem; }}
        .stats {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem; margin-bottom: 2rem;
        }}
        .stat {{
            background: var(--card); border: 1px solid var(--border);
            border-radius: 8px; padding: 1rem; text-align: center;
        }}
        .stat-value {{ font-size: 1.8rem; font-weight: bold; color: var(--accent); }}
        .stat-label {{ font-size: 0.85rem; color: #8b949e; }}
        .finding {{
            background: var(--card); border-radius: 8px;
            margin-bottom: 1rem; padding: 1rem;
            border: 1px solid var(--border);
        }}
        .finding-header {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem; }}
        .badge {{
            color: #fff; padding: 2px 8px; border-radius: 4px;
            font-size: 0.75rem; font-weight: bold;
        }}
        .confidence {{ margin-left: auto; color: #8b949e; font-size: 0.85rem; }}
        .finding-details p {{ margin: 0.25rem 0; }}
        .recommendation {{ color: #58a6ff; font-style: italic; margin-top: 0.5rem !important; }}
        code {{
            background: #1f2937; padding: 2px 6px; border-radius: 3px;
            font-family: 'Fira Code', monospace; font-size: 0.9em;
        }}
        .context-block {{
            background: #1f2937; border-radius: 4px; padding: 0.5rem;
            margin: 0.5rem 0; font-family: monospace; font-size: 0.85em;
            overflow-x: auto;
        }}
        .context-block .highlight {{ background: #3b1f1f; display: block; padding: 0 4px; }}
        .status-{status_class} {{ color: {"#3fb950" if status_class == "success" else "#f85149"}; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Secrets Scanner Report</h1>
        <p class="subtitle">
            {result.scan_path} &mdash;
            {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
        </p>
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{result.files_scanned}</div>
                <div class="stat-label">Files Scanned</div>
            </div>
            <div class="stat">
                <div class="stat-value status-{status_class}">{len(result.findings)}</div>
                <div class="stat-label">Secrets Found</div>
            </div>
            <div class="stat">
                <div class="stat-value">{counts.get('CRITICAL', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat">
                <div class="stat-value">{counts.get('HIGH', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat">
                <div class="stat-value">{result.duration_seconds:.1f}s</div>
                <div class="stat-label">Duration</div>
            </div>
        </div>
        {findings_html if result.findings else '<p style="text-align:center;color:#3fb950;font-size:1.2rem;">✅ No secrets detected.</p>'}
    </div>
</body>
</html>"""

        if output:
            output.write(html)

        return html

    @staticmethod
    def _render_context(finding: Finding) -> str:
        """Render context lines as an HTML block."""
        if not finding.context_before and not finding.context_after:
            return ""

        lines_html = ""
        start_num = finding.line_number - len(finding.context_before)

        for i, line in enumerate(finding.context_before):
            num = start_num + i
            escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            lines_html += f"<span>{num:>4} | {escaped}</span>\n"

        escaped_current = (
            finding.line_content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )
        lines_html += (
            f'<span class="highlight">{finding.line_number:>4} | {escaped_current}</span>\n'
        )

        for i, line in enumerate(finding.context_after):
            num = finding.line_number + 1 + i
            escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            lines_html += f"<span>{num:>4} | {escaped}</span>\n"

        return f'<div class="context-block"><pre>{lines_html}</pre></div>'


class SARIFReportGenerator(ReportGenerator):
    """Generates SARIF (Static Analysis Results Interchange Format) v2.1.0 reports."""

    def generate(self, result: ScanResult, output: TextIO | None = None) -> str:
        """Generate SARIF report.

        Args:
            result: Scan results.
            output: Optional output stream.

        Returns:
            SARIF JSON string.
        """
        driver_rules = []
        rules_added = set()
        results = []

        # Map internal severity to SARIF level
        level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
        }

        for finding in result.findings:
            # Add rule if not already present
            if finding.pattern_id not in rules_added:
                driver_rules.append(
                    {
                        "id": finding.pattern_id,
                        "name": finding.pattern_name,
                        "shortDescription": {"text": finding.pattern_name},
                        "fullDescription": {"text": finding.description or finding.pattern_name},
                        "properties": {
                            "precision": "high" if finding.confidence > 0.8 else "medium"
                        },
                    }
                )
                rules_added.add(finding.pattern_id)

            # Create SARIF result
            sarif_result = {
                "ruleId": finding.pattern_id,
                "level": level_map.get(finding.severity, "warning"),
                "message": {
                    "text": f"Secret detected: {finding.pattern_name}. Confidence: {finding.confidence:.0%}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path.replace("\\", "/")},
                            "region": {
                                "startLine": finding.line_number,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
            results.append(sarif_result)

        report_data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "dotenv-secrets-scanner",
                            "version": __version__,
                            "informationUri": "https://github.com/Quarrezz/dotenv-secrets-scanner",
                            "rules": driver_rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                }
            ],
        }

        json_str = json.dumps(report_data, indent=2)

        if output:
            output.write(json_str)

        return json_str


class ConsoleReportGenerator(ReportGenerator):
    """Generates Rich-formatted console output with colors and tables."""

    def generate(self, result: ScanResult, output: TextIO | None = None) -> str:
        """Generate console-friendly output using Rich markup.

        Note: This returns plain text with ANSI escape codes; the actual
        Rich rendering is done in the CLI layer. This method returns a
        summary string.

        Args:
            result: Scan results.
            output: Not used for console output.

        Returns:
            Summary text string.
        """
        # Console output is handled by the CLI layer using Rich directly.
        # This returns a simple summary for non-interactive usage.
        if not result.findings:
            return "✅ No secrets detected."

        lines = [f"🚨 {len(result.findings)} secret(s) detected!"]
        counts = result.severity_counts()
        for sev, count in counts.items():
            if count > 0:
                lines.append(f"  {sev}: {count}")

        return "\n".join(lines)


def generate_report(
    result: ScanResult,
    format: str = "console",
    output_path: Path | None = None,
) -> str:
    """Generate a report in the specified format.

    Args:
        result: Scan results to report.
        format: Output format ('json', 'text', 'html', 'console').
        output_path: If provided, write the report to this file.

    Returns:
        The generated report string.

    Raises:
        ValueError: If the format is not recognized.
    """
    generators: dict[str, ReportGenerator] = {
        "json": JSONReportGenerator(),
        "text": TextReportGenerator(),
        "html": HTMLReportGenerator(),
        "console": ConsoleReportGenerator(),
        "sarif": SARIFReportGenerator(),
    }

    generator = generators.get(format.lower())
    if generator is None:
        valid = ", ".join(generators.keys())
        raise ValueError(f"Unknown report format '{format}'. Valid formats: {valid}")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            return generator.generate(result, output=f)
    else:
        return generator.generate(result)
