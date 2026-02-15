"""Secret validation and false positive filtering.

Multi-layer validation pipeline to reduce false positives:
1. FalsePositiveFilter — eliminates known non-secret patterns
2. ContextAnalyzer — adjusts confidence based on file/line context
3. ConfidenceScorer — computes final confidence score
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.entropy import calculate_shannon_entropy, entropy_score

# ---------------------------------------------------------------------------
# Well-known placeholder / example values that are NOT secrets
# ---------------------------------------------------------------------------

_KNOWN_SAFE_VALUES: frozenset[str] = frozenset({
    # AWS documentation examples
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # Generic placeholders
    "your-api-key-here",
    "your_api_key",
    "replace-me",
    "changeme",
    "password",
    "password123",
    "p@ssw0rd",
    "admin",
    "root",
    "test",
    "demo",
    # Common in documentation
    "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
})

_SAFE_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in [
        # All same character
        r"^(.)\1+$",
        # Sequential patterns
        r"^(?:abc|123|000|111|aaa|xxx|yyy|zzz)",
        # Placeholder markers
        r"^(?:example|sample|test|dummy|fake|mock|placeholder|changeme|replace)(?:[_\-\s]|$)",
        r"(?:your[_-]|my[_-]|insert[_-]|enter[_-]|put[_-])",
        r"(?:TODO|FIXME|XXX|HACK)",
        # Template strings
        r"<[A-Z_]+>",
        r"\{\{.*\}\}",
        r"\$\{.*\}",
        r"%\(.*\)",
        r"\$[A-Z_]+",
        # Documentation markers
        r"(?:^sk-\.{3,}$)",
    ]
)

_TEST_FILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"test[_s]?", re.IGNORECASE),
    re.compile(r"spec[_s]?", re.IGNORECASE),
    re.compile(r"mock[_s]?", re.IGNORECASE),
    re.compile(r"fixture[_s]?", re.IGNORECASE),
    re.compile(r"__tests__", re.IGNORECASE),
)

_EXAMPLE_FILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\.example$", re.IGNORECASE),
    re.compile(r"\.sample$", re.IGNORECASE),
    re.compile(r"\.template$", re.IGNORECASE),
    re.compile(r"\.dist$", re.IGNORECASE),
)


class FalsePositiveFilter:
    """Filters out matches that are known false positives.

    Uses a combination of exact match lookup, regex pattern matching, and
    entropy checks to determine if a detected secret is likely a placeholder.
    """

    def is_false_positive(
        self,
        matched_text: str,
        line_content: str,
        pattern_false_positives: tuple[re.Pattern[str], ...] = (),
    ) -> bool:
        """Check if a matched value is a false positive.

        Args:
            matched_text: The text that matched a secret pattern.
            line_content: The full line containing the match.
            pattern_false_positives: Additional FP patterns from the SecretPattern.

        Returns:
            True if the match is likely a false positive.
        """
        # Exact match against known safe values
        if matched_text.strip("'\" ") in _KNOWN_SAFE_VALUES:
            return True

        cleaned = matched_text.strip("'\" ")

        # Check global safe value patterns
        for fp_pattern in _SAFE_VALUE_PATTERNS:
            if fp_pattern.search(cleaned):
                return True

        # Check pattern-specific false positive patterns
        for fp_pattern in pattern_false_positives:
            if fp_pattern.search(cleaned):
                return True

        # Check if the line is a comment
        stripped_line = line_content.strip()
        if stripped_line.startswith(("#", "//", "/*", "*", "<!--", "REM ", "'")):
            # Comments with examples are common false positives,
            # but only reduce confidence, not auto-reject.
            pass

        return False


class ContextAnalyzer:
    """Analyzes the surrounding context of a finding to adjust confidence.

    Considers:
    - File path (test files, example files, documentation)
    - Surrounding lines (comments, variable names)
    - File extension
    """

    # Confidence modifiers
    TEST_FILE_PENALTY = -0.25
    EXAMPLE_FILE_PENALTY = -0.35
    COMMENT_LINE_PENALTY = -0.15
    DOC_FILE_PENALTY = -0.20
    ENV_EXAMPLE_PENALTY = -0.40
    ASSIGNMENT_BONUS = 0.05

    def analyze(
        self,
        file_path: str,
        line_content: str,
        line_number: int,
        context_before: list[str] | None = None,
    ) -> float:
        """Calculate a confidence modifier based on context.

        Args:
            file_path: Path to the file being analyzed.
            line_content: The line containing the potential secret.
            line_number: The line number (1-based).
            context_before: Lines immediately before the finding.

        Returns:
            A modifier to add to the base confidence. Can be negative.
        """
        modifier = 0.0
        path = Path(file_path)
        filename = path.name.lower()
        stem = path.stem.lower()

        # Test file penalty
        for test_pat in _TEST_FILE_PATTERNS:
            if test_pat.search(stem):
                modifier += self.TEST_FILE_PENALTY
                break

        # Example / template file penalty
        for ex_pat in _EXAMPLE_FILE_PATTERNS:
            if ex_pat.search(filename):
                modifier += self.EXAMPLE_FILE_PENALTY
                break

        # .env.example / .env.sample
        if filename in (".env.example", ".env.sample", ".env.template", ".env.dist"):
            modifier += self.ENV_EXAMPLE_PENALTY

        # Documentation files
        if path.suffix.lower() in (".md", ".rst", ".txt", ".adoc"):
            modifier += self.DOC_FILE_PENALTY

        # Comment line penalty
        stripped = line_content.strip()
        if stripped.startswith(("#", "//", "/*", "*", "<!--")):
            modifier += self.COMMENT_LINE_PENALTY

        # Assignment pattern bonus (more likely real)
        if re.search(r"[=:]\s*['\"]", line_content):
            modifier += self.ASSIGNMENT_BONUS

        return modifier


class ConfidenceScorer:
    """Computes the final confidence score for a finding.

    Combines:
    1. Base pattern confidence
    2. Entropy signal
    3. Context modifier (from ContextAnalyzer)

    The final score is clamped between 0.0 and 1.0.
    """

    ENTROPY_WEIGHT = 0.15

    def __init__(self) -> None:
        self._context_analyzer = ContextAnalyzer()

    def score(
        self,
        base_confidence: float,
        matched_text: str,
        file_path: str,
        line_content: str,
        line_number: int,
        context_before: list[str] | None = None,
        entropy_threshold: float | None = None,
    ) -> float:
        """Calculate the final confidence score.

        Args:
            base_confidence: Pattern's base confidence.
            matched_text: The matched secret text.
            file_path: Path to the file.
            line_content: Full line content.
            line_number: Line number (1-based).
            context_before: Lines before the finding.
            entropy_threshold: Optional entropy threshold for bonus/penalty.

        Returns:
            Final confidence between 0.0 and 1.0.
        """
        score = base_confidence

        # Entropy component
        cleaned = matched_text.strip("'\" ")
        if cleaned:
            ent_score = entropy_score(cleaned)

            if entropy_threshold is not None:
                ent = calculate_shannon_entropy(cleaned)
                if ent < entropy_threshold:
                    # Below entropy threshold — significant penalty
                    score -= 0.20
                else:
                    score += ent_score * self.ENTROPY_WEIGHT
            else:
                score += ent_score * self.ENTROPY_WEIGHT

        # Context modifier
        context_mod = self._context_analyzer.analyze(
            file_path=file_path,
            line_content=line_content,
            line_number=line_number,
            context_before=context_before,
        )
        score += context_mod

        # Clamp to valid range
        return max(0.0, min(1.0, score))
