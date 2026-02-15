"""Configuration management for the secrets scanner.

Handles loading and merging configuration from:
1. Default values (ScanConfig defaults)
2. Config file (.secretscan.yml)
3. .secretsignore file
4. CLI arguments (highest priority)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from scanner.models import ScanConfig, Severity

logger = logging.getLogger("scanner")

# Well-known config file names, checked in order
CONFIG_FILE_NAMES = (
    ".secretscan.yml",
    ".secretscan.yaml",
    "secretscan.yml",
    "secretscan.yaml",
)

SECRETSIGNORE_FILE_NAMES = (
    ".secretsignore",
)


def find_config_file(search_dir: Path) -> Path | None:
    """Search for a config file in the given directory.

    Args:
        search_dir: Directory to search in.

    Returns:
        Path to config file, or None if not found.
    """
    for name in CONFIG_FILE_NAMES:
        candidate = search_dir / name
        if candidate.is_file():
            return candidate
    return None


def find_secretsignore(search_dir: Path) -> Path | None:
    """Search for a .secretsignore file in the given directory.

    Args:
        search_dir: Directory to search in.

    Returns:
        Path to .secretsignore file, or None if not found.
    """
    for name in SECRETSIGNORE_FILE_NAMES:
        candidate = search_dir / name
        if candidate.is_file():
            return candidate
    return None


def load_secretsignore(path: Path) -> list[str]:
    """Load and parse a .secretsignore file.

    Format is similar to .gitignore:
    - One pattern per line
    - Lines starting with # are comments
    - Empty lines are ignored
    - Supports glob patterns for file paths
    - Supports pattern:file:line format for specific suppression

    Args:
        path: Path to the .secretsignore file.

    Returns:
        List of ignore pattern strings.
    """
    patterns: list[str] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    patterns.append(stripped)
    except OSError as exc:
        logger.warning("Could not read .secretsignore at %s: %s", path, exc)

    return patterns


def load_config_file(path: Path) -> dict[str, Any]:
    """Load a YAML config file.

    Args:
        path: Path to the YAML config file.

    Returns:
        Parsed configuration dictionary.

    Raises:
        ValueError: If the file cannot be parsed.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise ValueError(f"Config file must be a YAML mapping, got {type(data).__name__}")
            return data
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in config file {path}: {exc}") from exc


def load_config(
    config_path: Path | None = None,
    scan_dir: Path | None = None,
) -> ScanConfig:
    """Load and merge configuration from all sources.

    Priority (highest to lowest):
    1. Explicit config_path
    2. Auto-discovered config file in scan_dir
    3. Default ScanConfig values

    Args:
        config_path: Explicit path to a config file.
        scan_dir: Directory to search for auto-discovered config.

    Returns:
        Merged ScanConfig instance.
    """
    config = ScanConfig()
    file_config: dict[str, Any] = {}

    # Load config file
    if config_path and config_path.is_file():
        file_config = load_config_file(config_path)
    elif scan_dir:
        discovered = find_config_file(scan_dir)
        if discovered:
            logger.info("Using config file: %s", discovered)
            file_config = load_config_file(discovered)

    # Apply config file values
    if file_config:
        config = _apply_file_config(config, file_config)

    # Load .secretsignore
    if scan_dir:
        ignore_path = find_secretsignore(scan_dir)
        if ignore_path:
            logger.info("Using .secretsignore: %s", ignore_path)
            config.secretsignore_patterns = load_secretsignore(ignore_path)

    return config


def _apply_file_config(config: ScanConfig, data: dict[str, Any]) -> ScanConfig:
    """Apply YAML config values to a ScanConfig.

    Args:
        config: Base config to modify.
        data: Parsed YAML data.

    Returns:
        Updated ScanConfig.
    """
    if "severity" in data:
        config.min_severity = Severity.from_string(str(data["severity"]))

    if "max_file_size" in data:
        config.max_file_size_bytes = int(data["max_file_size"])

    if "excluded_dirs" in data:
        extra = frozenset(str(d) for d in data["excluded_dirs"])
        config.excluded_dirs = config.excluded_dirs | extra

    if "excluded_extensions" in data:
        extra = frozenset(str(e) for e in data["excluded_extensions"])
        config.excluded_extensions = config.excluded_extensions | extra

    if "context_lines" in data:
        config.context_lines = int(data["context_lines"])

    if "max_workers" in data:
        config.max_workers = int(data["max_workers"])

    if "follow_symlinks" in data:
        config.follow_symlinks = bool(data["follow_symlinks"])

    if "scan_hidden" in data:
        config.scan_hidden = bool(data["scan_hidden"])

    if "respect_gitignore" in data:
        config.respect_gitignore = bool(data["respect_gitignore"])

    # Custom patterns from YAML config
    if "custom_patterns" in data and isinstance(data["custom_patterns"], list):
        from scanner.models import SecretPattern

        for p in data["custom_patterns"]:
            if not isinstance(p, dict):
                logger.warning("Skipping invalid custom pattern entry: %s", p)
                continue

            pattern_str = p.get("pattern")
            if not pattern_str:
                logger.warning("Custom pattern missing 'pattern' field: %s", p)
                continue

            try:
                import re
                compiled = re.compile(pattern_str)
            except re.error as exc:
                logger.warning("Invalid regex in custom pattern '%s': %s", pattern_str, exc)
                continue

            severity = Severity.MEDIUM
            if "severity" in p:
                try:
                    severity = Severity.from_string(str(p["severity"]))
                except ValueError:
                    logger.warning("Invalid severity '%s', defaulting to MEDIUM", p["severity"])

            custom = SecretPattern(
                id=str(p.get("id", f"custom-{len(config.custom_patterns)}")),
                name=str(p.get("name", p.get("id", "Custom Pattern"))),
                pattern=compiled,
                severity=severity,
                confidence=float(p.get("confidence", 0.85)),
                description=str(p.get("description", "")),
            )
            config.custom_patterns.append(custom)

        if config.custom_patterns:
            logger.info("Loaded %d custom pattern(s) from config.", len(config.custom_patterns))

    return config


def merge_cli_args(config: ScanConfig, **kwargs: Any) -> ScanConfig:
    """Merge CLI arguments into an existing config.

    Only non-None values override the config.

    Args:
        config: Base configuration.
        **kwargs: CLI argument key-value pairs.

    Returns:
        Updated ScanConfig.
    """
    if kwargs.get("severity"):
        config.min_severity = Severity.from_string(kwargs["severity"])

    if kwargs.get("max_file_size"):
        config.max_file_size_bytes = kwargs["max_file_size"]

    if kwargs.get("exclude"):
        extra = frozenset(kwargs["exclude"])
        config.excluded_dirs = config.excluded_dirs | extra

    if kwargs.get("context_lines") is not None:
        config.context_lines = kwargs["context_lines"]

    if kwargs.get("workers") is not None:
        config.max_workers = kwargs["workers"]

    return config
