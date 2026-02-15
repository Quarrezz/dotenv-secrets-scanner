# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-15

### Added
- **Standardized CLI:** Unified command `secrets-scan` for all operations.
- **SARIF Support:** Added SARIF output format for GitHub Code Scanning integration.
- **Docker Support:** Official `Dockerfile` and GitHub Actions workflow for publishing to GHCR.
- **Regional Patterns:** Added support for Iyzico, PayTR, Türk Telekom Cloud, and e-Devlet API keys.
- **Entropy Analysis:** Implemented Shannon entropy detection to find high-entropy secrets (random strings).
- **Baseline System:** Added `baseline.json` support to suppress existing findings.
- **Pre-commit Hook:** Native support for git pre-commit hooks via `secrets-scan install-hook`.

### Changed
- **Performance:** Optimized scanning engine with multi-threading and file filtering.
- **Configuration:** improved `.secretscan.yml` and `.secretsignore` handling.
- **Docs:** Comprehensive `README.md` with usage examples and architecture overview.

### Fixed
- Addressed various linting issues and type checking errors.
- Fixed CLI entry point to ensure consistent behavior across platforms.
- Normalized git line endings to LF to fix CI inconsistencies.
