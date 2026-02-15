"""Git integration for secrets scanning.

Provides functionality for:
- Scanning staged files (pre-commit hook)
- Scanning commit history
- Detecting git repositories
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from scanner.core import SecretScanner

if TYPE_CHECKING:
    from scanner.models import Finding, ScanConfig

logger = logging.getLogger("scanner")


def is_git_repo(path: Path) -> bool:
    """Check if a path is inside a Git repository.

    Args:
        path: Path to check.

    Returns:
        True if the path is within a Git repo.
    """
    try:
        import git

        git.Repo(str(path), search_parent_directories=True)
        return True
    except Exception:
        return False


def get_repo_root(path: Path) -> Path | None:
    """Get the root directory of the Git repository.

    Args:
        path: Any path within the repo.

    Returns:
        Root directory path, or None if not a Git repo.
    """
    try:
        import git

        repo = git.Repo(str(path), search_parent_directories=True)
        working_dir = repo.working_dir
        if working_dir is None:
            return None
        return Path(working_dir)
    except Exception:
        return None


def get_staged_files(repo_path: Path) -> list[Path]:
    """Get list of files staged for the next commit.

    Args:
        repo_path: Path to the Git repository.

    Returns:
        List of absolute paths to staged files.
    """
    try:
        import git

        repo = git.Repo(str(repo_path), search_parent_directories=True)
        staged = repo.index.diff("HEAD")

        files: list[Path] = []
        working_dir = repo.working_dir
        if working_dir is None:
            return files

        root = Path(working_dir)
        for diff in staged:
            if diff.a_path:
                file_path = root / diff.a_path
                if file_path.exists() and file_path.is_file():
                    files.append(file_path)

        # Also include untracked files that are staged
        for item in repo.index.diff(None):
            if item.a_path:
                file_path = root / item.a_path
                if file_path.exists() and file_path.is_file() and file_path not in files:
                    files.append(file_path)

        return files

    except Exception as exc:
        logger.warning("Could not get staged files: %s", exc)
        return []


def scan_staged_files(
    repo_path: Path,
    config: ScanConfig | None = None,
) -> list[Finding]:
    """Scan all staged files for secrets.

    Args:
        repo_path: Path to the Git repository.
        config: Scan configuration.

    Returns:
        List of findings from staged files.
    """
    scanner = SecretScanner(config=config)
    staged = get_staged_files(repo_path)

    all_findings: list[Finding] = []
    for file_path in staged:
        try:
            findings = scanner.scan_file(file_path)
            all_findings.extend(findings)
        except Exception as exc:
            logger.warning("Error scanning staged file %s: %s", file_path, exc)

    return all_findings


def scan_git_history(
    repo_path: Path,
    max_commits: int = 50,
    config: ScanConfig | None = None,
) -> list[Finding]:
    """Scan Git commit history for secrets.

    Examines the diff of each commit to find secrets that were ever committed.

    Args:
        repo_path: Path to the Git repository.
        max_commits: Maximum number of commits to scan.
        config: Scan configuration.

    Returns:
        List of findings from commit history.
    """
    try:
        import git
    except ImportError:
        logger.error("GitPython is required for history scanning.")
        return []

    scanner = SecretScanner(config=config)
    all_findings: list[Finding] = []

    try:
        repo = git.Repo(str(repo_path), search_parent_directories=True)
    except git.InvalidGitRepositoryError:
        logger.error("Not a valid Git repository: %s", repo_path)
        return []

    try:
        commits = list(repo.iter_commits(max_count=max_commits))
    except Exception as exc:
        logger.error("Could not read commit history: %s", exc)
        return []

    for commit in commits:
        try:
            # Get the diff for this commit
            if commit.parents:
                diffs = commit.diff(commit.parents[0], create_patch=True)
            else:
                # Initial commit — diff against empty tree
                diffs = commit.diff(git.NULL_TREE, create_patch=True)

            for diff in diffs:
                raw_diff = diff.diff
                if not raw_diff:
                    continue

                if isinstance(raw_diff, bytes):
                    content = raw_diff.decode("utf-8", errors="replace")
                else:
                    content = str(raw_diff)

                # Only scan added lines
                added_lines: list[str] = []
                for line in content.splitlines():
                    if line.startswith("+") and not line.startswith("+++"):
                        added_lines.append(line[1:])

                if added_lines:
                    source = f"{diff.a_path or diff.b_path} (commit {commit.hexsha[:8]})"
                    findings = scanner.scan_content(
                        "\n".join(added_lines),
                        source=source,
                    )
                    for finding in findings:
                        finding.commit_hash = commit.hexsha
                        all_findings.append(finding)

        except Exception as exc:
            logger.debug("Error scanning commit %s: %s", commit.hexsha[:8], exc)

    return all_findings


def get_diff_files(repo_path: Path, base_ref: str = "HEAD~1") -> list[Path]:
    """Get files changed between a ref and the current state.

    Args:
        repo_path: Path to the Git repository.
        base_ref: Git ref to compare against (default: previous commit).

    Returns:
        List of changed file paths.
    """
    try:
        import git

        repo = git.Repo(str(repo_path), search_parent_directories=True)
        working_dir = repo.working_dir
        if working_dir is None:
            return []

        root = Path(working_dir)
        diffs = repo.head.commit.diff(base_ref)

        files: list[Path] = []
        for diff in diffs:
            path_str = diff.b_path or diff.a_path
            if path_str:
                file_path = root / path_str
                if file_path.exists() and file_path.is_file():
                    files.append(file_path)

        return files

    except Exception as exc:
        logger.warning("Could not get diff files: %s", exc)
        return []
