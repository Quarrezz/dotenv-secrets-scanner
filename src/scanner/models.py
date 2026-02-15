"""Data models for the secrets scanner.

Defines all core data structures used throughout the application:
- Severity levels for findings
- Secret pattern definitions
- Scan findings and results
- Scanner configuration
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import re


class Severity(IntEnum):
    """Severity level for a detected secret.

    Ordered from lowest to highest for comparison and filtering.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """Parse a severity from its string name.

        Args:
            value: Case-insensitive severity name.

        Returns:
            The corresponding Severity enum member.

        Raises:
            ValueError: If the value doesn't match any severity.
        """
        normalized = value.strip().upper()
        try:
            return cls[normalized]
        except KeyError:
            valid = ", ".join(s.name for s in cls)
            raise ValueError(f"Invalid severity '{value}'. Valid values: {valid}") from None


@dataclass(frozen=True)
class SecretPattern:
    """Definition of a secret pattern to scan for.

    Attributes:
        id: Unique identifier, e.g. 'aws-access-key'.
        name: Human-readable name, e.g. 'AWS Access Key'.
        pattern: Compiled regex for detection.
        severity: How critical this secret type is.
        confidence: Base confidence score (0.0 - 1.0).
        description: Human-readable explanation of what this pattern detects.
        secret_group: Regex group index that contains the actual secret value.
        false_positive_patterns: Regex patterns that indicate a false positive.
        entropy_threshold: Minimum Shannon entropy for the matched secret.
            None means entropy check is skipped.
        validators: Names of validator functions to apply after matching.
    """

    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float
    description: str
    secret_group: int = 0
    false_positive_patterns: tuple[re.Pattern[str], ...] = ()
    entropy_threshold: float | None = None
    validators: tuple[str, ...] = ()


@dataclass
class Finding:
    """A single detected secret finding.

    Attributes:
        pattern_id: ID of the matched pattern.
        pattern_name: Human-readable pattern name.
        severity: Severity of this finding.
        file_path: Path to the file containing the secret.
        line_number: 1-based line number.
        line_content: The full line containing the secret.
        matched_text: The exact text that matched the pattern.
        masked_secret: The secret value with middle characters replaced.
        confidence: Final confidence score after all validation layers.
        context_before: Lines before the match for context.
        context_after: Lines after the match for context.
        commit_hash: Git commit hash, if scanned from history.
        description: Human-readable description of the finding.
        recommendation: Suggested fix action.
    """

    pattern_id: str
    pattern_name: str
    severity: Severity
    file_path: str
    line_number: int
    line_content: str
    matched_text: str
    masked_secret: str
    confidence: float
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    commit_hash: str | None = None
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a dictionary for JSON output.

        Returns:
            Dictionary representation with all fields.
        """
        return {
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "severity": self.severity.name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "matched_text": self.masked_secret,  # Never expose the raw secret
            "confidence": round(self.confidence, 2),
            "context_before": self.context_before,
            "context_after": self.context_after,
            "commit_hash": self.commit_hash,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanResult:
    """Aggregated results of a scan operation.

    Attributes:
        findings: All detected secrets.
        files_scanned: Number of files scanned.
        files_skipped: Number of files skipped (binary, too large, ignored).
        duration_seconds: How long the scan took.
        scan_path: The root path that was scanned.
        errors: List of errors encountered during scanning.
    """

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    duration_seconds: float = 0.0
    scan_path: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def has_secrets(self) -> bool:
        """Whether any secrets were found."""
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        """Number of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Number of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Number of LOW severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    def severity_counts(self) -> dict[str, int]:
        """Get counts grouped by severity.

        Returns:
            Dictionary mapping severity names to their counts.
        """
        return {
            "CRITICAL": self.critical_count,
            "HIGH": self.high_count,
            "MEDIUM": self.medium_count,
            "LOW": self.low_count,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the scan result to a dictionary for JSON output.

        Returns:
            Dictionary representation with stats and findings.
        """
        return {
            "scan_path": self.scan_path,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


@dataclass
class ScanConfig:
    """Configuration for a scan operation.

    Attributes:
        min_severity: Minimum severity threshold to report.
        max_file_size_bytes: Skip files larger than this (default 1MB).
        excluded_dirs: Directory names to skip.
        excluded_extensions: File extensions to skip.
        custom_patterns: Additional user-defined patterns.
        secretsignore_patterns: Patterns from .secretsignore to suppress.
        context_lines: Number of context lines to include around findings.
        max_workers: Number of parallel threads for scanning.
        follow_symlinks: Whether to follow symbolic links.
        scan_hidden: Whether to scan hidden files/directories.
        respect_gitignore: Whether to respect .gitignore patterns.
    """

    min_severity: Severity = Severity.LOW
    max_file_size_bytes: int = 1_048_576  # 1MB
    excluded_dirs: frozenset[str] = frozenset({
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".eggs",
        "vendor",
    })
    excluded_extensions: frozenset[str] = frozenset({
        ".pyc",
        ".pyo",
        ".so",
        ".dll",
        ".exe",
        ".bin",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".bmp",
        ".ico",
        ".svg",
        ".webp",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".7z",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".lock",
    })
    custom_patterns: list[SecretPattern] = field(default_factory=list)
    secretsignore_patterns: list[str] = field(default_factory=list)
    context_lines: int = 2
    max_workers: int = 4
    follow_symlinks: bool = False
    scan_hidden: bool = False
    respect_gitignore: bool = True
