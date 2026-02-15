"""Core scanning engine.

Orchestrates the scanning pipeline: file discovery → line tokenization →
pattern matching → validation → finding aggregation.

Thread-safe design with configurable parallelism for large repositories.
"""

from __future__ import annotations

import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from fnmatch import fnmatch
from pathlib import Path
from typing import IO

from scanner.entropy import calculate_shannon_entropy
from scanner.models import Finding, ScanConfig, ScanResult, SecretPattern, Severity
from scanner.patterns import PatternRegistry, create_default_registry
from scanner.validators import ConfidenceScorer, FalsePositiveFilter

logger = logging.getLogger("scanner")

# Maximum line length to scan — avoids DoS on minified files
_MAX_LINE_LENGTH = 2000

# Binary file detection: if a sample of the file contains null bytes, skip it
_BINARY_SAMPLE_SIZE = 8192

# Minimum confidence threshold to report a finding
_MIN_REPORT_CONFIDENCE = 0.30


class SecretScanner:
    """Main scanning engine for detecting secrets in files and directories.

    Uses a multi-layer pipeline:
    1. File filtering (binary, size, ignore patterns)
    2. Line-by-line pattern matching
    3. Entropy validation
    4. False positive filtering
    5. Confidence scoring

    Attributes:
        config: Scan configuration.
        registry: Pattern registry to use.

    Example:
        scanner = SecretScanner(ScanConfig())
        result = scanner.scan_directory(Path("."))
        for finding in result.findings:
            print(f"{finding.severity}: {finding.pattern_name} in {finding.file_path}")
    """

    def __init__(
        self,
        config: ScanConfig | None = None,
        registry: PatternRegistry | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.registry = registry or create_default_registry()
        self._fp_filter = FalsePositiveFilter()
        self._scorer = ConfidenceScorer()

        # Register any custom patterns from config
        for custom_pattern in self.config.custom_patterns:
            if custom_pattern.id not in self.registry:
                self.registry.register(custom_pattern)

    def scan_directory(self, dir_path: Path) -> ScanResult:
        """Scan all files in a directory recursively.

        Args:
            dir_path: Root directory to scan.

        Returns:
            Aggregated scan results.
        """
        start_time = time.monotonic()
        result = ScanResult(scan_path=str(dir_path))

        files_to_scan = list(self._discover_files(dir_path))

        if not files_to_scan:
            result.duration_seconds = time.monotonic() - start_time
            return result

        if self.config.max_workers <= 1:
            for file_path in files_to_scan:
                self._scan_file_safe(file_path, result)
        else:
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = {
                    executor.submit(self.scan_file, fp): fp
                    for fp in files_to_scan
                }
                for future in as_completed(futures):
                    file_path = futures[future]
                    try:
                        findings = future.result()
                        result.findings.extend(findings)
                        result.files_scanned += 1
                    except Exception as exc:
                        error_msg = f"Error scanning {file_path}: {exc}"
                        logger.warning(error_msg)
                        result.errors.append(error_msg)
                        result.files_skipped += 1

        result.duration_seconds = time.monotonic() - start_time
        return result

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file for secrets.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings in the file.

        Raises:
            OSError: If the file cannot be read.
        """
        if self._should_skip_file(file_path):
            return []

        try:
            lines = self._read_file_lines(file_path)
        except (OSError, UnicodeDecodeError) as exc:
            logger.debug("Skipping %s: %s", file_path, exc)
            return []

        return self._scan_lines(lines, str(file_path))

    def scan_content(self, content: str, source: str = "<string>") -> list[Finding]:
        """Scan arbitrary string content for secrets.

        Args:
            content: The text content to scan.
            source: Identifier for the source (used in findings).

        Returns:
            List of findings.
        """
        lines = content.splitlines(keepends=True)
        return self._scan_lines(lines, source)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _scan_file_safe(self, file_path: Path, result: ScanResult) -> None:
        """Scan a file and accumulate results, catching errors."""
        try:
            findings = self.scan_file(file_path)
            result.findings.extend(findings)
            result.files_scanned += 1
        except Exception as exc:
            error_msg = f"Error scanning {file_path}: {exc}"
            logger.warning(error_msg)
            result.errors.append(error_msg)
            result.files_skipped += 1

    def _scan_lines(self, lines: list[str], source: str) -> list[Finding]:
        """Run pattern matching across all lines of a file.

        Args:
            lines: List of lines (with newlines).
            source: Source identifier (file path or label).

        Returns:
            List of validated findings.
        """
        findings: list[Finding] = []
        patterns = self.registry.get_by_severity(self.config.min_severity)

        for line_idx, line in enumerate(lines):
            line_num = line_idx + 1
            stripped_line = line.rstrip("\n\r")

            # Skip very long lines (minified files, data blobs)
            if len(stripped_line) > _MAX_LINE_LENGTH:
                continue

            for pattern in patterns:
                for match in pattern.pattern.finditer(stripped_line):
                    finding = self._process_match(
                        match=match,
                        pattern=pattern,
                        line_content=stripped_line,
                        line_number=line_num,
                        file_path=source,
                        all_lines=lines,
                    )
                    if finding is not None:
                        findings.append(finding)

        return findings

    def _process_match(
        self,
        match: "re.Match[str]",
        pattern: SecretPattern,
        line_content: str,
        line_number: int,
        file_path: str,
        all_lines: list[str],
    ) -> Finding | None:
        """Validate a regex match and create a Finding if it passes all checks.

        Args:
            match: The regex match object.
            pattern: The matched SecretPattern.
            line_content: The full line.
            line_number: 1-based line number.
            file_path: File path.
            all_lines: All lines for context extraction.

        Returns:
            A Finding if the match passes validation, None otherwise.
        """
        try:
            matched_text = match.group(pattern.secret_group)
        except IndexError:
            matched_text = match.group(0)

        if not matched_text or len(matched_text.strip()) < 4:
            return None

        # Layer 1: False positive filter
        if self._fp_filter.is_false_positive(
            matched_text=matched_text,
            line_content=line_content,
            pattern_false_positives=pattern.false_positive_patterns,
        ):
            return None

        # Layer 2: Entropy check
        if pattern.entropy_threshold is not None:
            cleaned = matched_text.strip("'\" ")
            entropy = calculate_shannon_entropy(cleaned)
            if entropy < pattern.entropy_threshold:
                return None

        # Layer 3: Secretsignore check
        if self._is_ignored(matched_text, file_path, line_number):
            return None

        # Layer 4: Severity check
        if pattern.severity < self.config.min_severity:
            return None

        # Layer 5: Confidence scoring
        context_before = self._get_context(all_lines, line_number, before=True)
        context_after = self._get_context(all_lines, line_number, before=False)

        confidence = self._scorer.score(
            base_confidence=pattern.confidence,
            matched_text=matched_text,
            file_path=file_path,
            line_content=line_content,
            line_number=line_number,
            context_before=context_before,
            entropy_threshold=pattern.entropy_threshold,
        )

        if confidence < _MIN_REPORT_CONFIDENCE:
            return None

        return Finding(
            pattern_id=pattern.id,
            pattern_name=pattern.name,
            severity=pattern.severity,
            file_path=file_path,
            line_number=line_number,
            line_content=line_content,
            matched_text=matched_text,
            masked_secret=self._mask_secret(matched_text),
            confidence=confidence,
            context_before=context_before,
            context_after=context_after,
            description=pattern.description,
            recommendation=self._get_recommendation(pattern),
        )

    def _discover_files(self, root: Path) -> list[Path]:
        """Recursively discover scannable files under a directory.

        Args:
            root: Root directory.

        Yields:
            Paths to files that pass all skip checks.
        """
        files: list[Path] = []
        try:
            for entry in sorted(root.iterdir()):
                # Skip symlinks if not configured to follow them
                if not self.config.follow_symlinks and entry.is_symlink():
                    continue

                if entry.is_dir():
                    dirname = entry.name
                    if dirname in self.config.excluded_dirs:
                        continue
                    if not self.config.scan_hidden and dirname.startswith("."):
                        continue
                    files.extend(self._discover_files(entry))
                elif entry.is_file():
                    if not self._should_skip_file(entry):
                        files.append(entry)
        except PermissionError:
            logger.debug("Permission denied: %s", root)
        return files

    def _should_skip_file(self, file_path: Path) -> bool:
        """Determine if a file should be skipped.

        Checks:
        - Excluded extension
        - File size limit
        - Binary content
        - Hidden file
        """
        # Extension check
        if file_path.suffix.lower() in self.config.excluded_extensions:
            return True

        # Hidden file check
        if not self.config.scan_hidden and file_path.name.startswith("."):
            # Exception: .env files are always scanned
            if not file_path.name.startswith(".env"):
                return True

        # Size check
        try:
            size = file_path.stat().st_size
            if size > self.config.max_file_size_bytes or size == 0:
                return True
        except OSError:
            return True

        # Binary check
        if self._is_binary(file_path):
            return True

        return False

    @staticmethod
    def _is_binary(file_path: Path) -> bool:
        """Check if a file appears to be binary by looking for null bytes."""
        try:
            with open(file_path, "rb") as f:
                sample = f.read(_BINARY_SAMPLE_SIZE)
                return b"\x00" in sample
        except OSError:
            return True

    @staticmethod
    def _read_file_lines(file_path: Path) -> list[str]:
        """Read file lines with encoding fallback.

        Tries UTF-8 first, then falls back to latin-1 (which never fails).
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                return f.readlines()
        except UnicodeDecodeError:
            with open(file_path, encoding="latin-1") as f:
                return f.readlines()

    @staticmethod
    def _mask_secret(secret: str) -> str:
        """Mask inner characters of a secret for safe display.

        Shows first 4 and last 4 characters, replaces middle with asterisks.
        Short secrets get more aggressive masking.

        Args:
            secret: Raw secret text.

        Returns:
            Masked version, e.g. 'AKIA************MPLE'.
        """
        cleaned = secret.strip("'\" ")
        length = len(cleaned)

        if length <= 8:
            return cleaned[:2] + "*" * (length - 2)
        elif length <= 16:
            return cleaned[:3] + "*" * (length - 6) + cleaned[-3:]
        else:
            return cleaned[:4] + "*" * (length - 8) + cleaned[-4:]

    def _get_context(
        self,
        lines: list[str],
        line_number: int,
        before: bool,
    ) -> list[str]:
        """Extract context lines around a finding.

        Args:
            lines: All file lines.
            line_number: 1-based line number of the finding.
            before: True for lines before, False for lines after.

        Returns:
            List of context lines (cleaned).
        """
        count = self.config.context_lines
        idx = line_number - 1  # Convert to 0-based

        if before:
            start = max(0, idx - count)
            end = idx
        else:
            start = idx + 1
            end = min(len(lines), idx + count + 1)

        return [line.rstrip("\n\r") for line in lines[start:end]]

    def _is_ignored(
        self,
        matched_text: str,
        file_path: str,
        line_number: int,
    ) -> bool:
        """Check if a finding should be suppressed by .secretsignore rules.

        Args:
            matched_text: The matched secret text.
            file_path: Path to the file.
            line_number: Line number.

        Returns:
            True if the finding should be ignored.
        """
        for ignore_pattern in self.config.secretsignore_patterns:
            ignore_pattern = ignore_pattern.strip()
            if not ignore_pattern or ignore_pattern.startswith("#"):
                continue

            # File path matching
            if fnmatch(file_path, ignore_pattern):
                return True

            # Pattern:file:line format
            if ":" in ignore_pattern:
                parts = ignore_pattern.split(":", maxsplit=2)
                if len(parts) >= 2:
                    if fnmatch(file_path, parts[0]) or parts[0] == "*":
                        if parts[1] == "*" or parts[1] == str(line_number):
                            return True

        return False

    @staticmethod
    def _get_recommendation(pattern: SecretPattern) -> str:
        """Generate a recommendation message for a finding.

        Args:
            pattern: The matched pattern.

        Returns:
            Human-readable recommendation string.
        """
        recommendations: dict[str, str] = {
            "aws-access-key": "Move to environment variable or use AWS IAM role.",
            "aws-secret-key": "Move to environment variable. Use aws configure or IAM role.",
            "github-pat": "Move to GitHub Secrets. Rotate the token.",
            "github-oauth": "Rotate the OAuth token and move to secure storage.",
            "github-app-token": "Move token to .env file or vault.",
            "stripe-secret-key": "Move to environment variable. Rotate key in Stripe Dashboard.",
            "stripe-restricted-key": "Move restricted key to secure storage.",
            "private-ssh-key": "Remove SSH key from file. Use ssh-agent.",
            "postgres-connection-string": "Move connection string to environment variable.",
            "mysql-connection-string": "Move connection string to environment variable.",
            "openai-api-key": "Move to environment variable. Rotate key in OpenAI dashboard.",
            "openai-api-key-v2": "Move to environment variable. Rotate key in OpenAI dashboard.",
            "google-api-key": "Move to environment variable. Configure key restrictions.",
            "slack-bot-token": "Move token to secure storage.",
            "slack-user-token": "Move token to secure storage.",
            "slack-webhook": "Move Webhook URL to environment variable.",
            "jwt-token": "Remove JWT from code. Use dynamic token generation.",
            "sendgrid-api-key": "Move to environment variable. Rotate the key.",
            "iyzico-api-key": "Move to environment variable. Rotate key in Iyzico panel.",
            "iyzico-secret-key": "Move to environment variable. Rotate key in Iyzico panel.",
            "paytr-merchant-key": "Move to environment variable. Rotate key in PayTR panel.",
        }
        return recommendations.get(
            pattern.id,
            "Move this value to an environment variable.",
        )
