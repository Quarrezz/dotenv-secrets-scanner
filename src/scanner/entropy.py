"""Shannon entropy analysis for secret detection.

Entropy is a measure of randomness in a string. Secrets tend to have high
entropy because they are randomly generated. This module provides functions
to calculate entropy and detect encoded content.
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from enum import Enum


class EncodingType(Enum):
    """Detected encoding type of a string."""

    PLAINTEXT = "plaintext"
    BASE64 = "base64"
    HEX = "hex"
    BASE32 = "base32"


# Pre-compiled character sets for encoding detection
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{16,}$")
_BASE64_URL_RE = re.compile(r"^[A-Za-z0-9_-]{16,}={0,2}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_BASE32_RE = re.compile(r"^[A-Z2-7=]{16,}$")

# Entropy thresholds tuned for different encoding types
ENTROPY_THRESHOLDS: dict[EncodingType, float] = {
    EncodingType.PLAINTEXT: 3.5,
    EncodingType.BASE64: 4.0,
    EncodingType.HEX: 3.0,
    EncodingType.BASE32: 3.5,
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string.

    Shannon entropy measures how unpredictable a string is. Higher values
    indicate more randomness. A purely random base64 string of sufficient
    length will have entropy close to log2(64) ≈ 6.0.

    Args:
        data: Input string to analyze.

    Returns:
        Shannon entropy in bits. Returns 0.0 for empty strings.

    Example:
        >>> calculate_shannon_entropy("aaaa")
        0.0
        >>> calculate_shannon_entropy("AKIAIOSFODNN7EXAMPLE")  # ~3.7
        3.684...
    """
    if not data:
        return 0.0

    length = len(data)
    counter = Counter(data)
    entropy = 0.0

    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def calculate_charset_diversity(data: str) -> float:
    """Calculate charset diversity ratio.

    Measures what fraction of distinct character categories are used:
    lowercase, uppercase, digits, and symbols.

    Args:
        data: Input string to analyze.

    Returns:
        Diversity ratio between 0.0 (single category) and 1.0 (all categories).
    """
    if not data:
        return 0.0

    categories_present = 0
    total_categories = 4

    has_lower = any(c in string.ascii_lowercase for c in data)
    has_upper = any(c in string.ascii_uppercase for c in data)
    has_digit = any(c in string.digits for c in data)
    has_special = any(c not in string.ascii_letters + string.digits for c in data)

    categories_present = sum([has_lower, has_upper, has_digit, has_special])
    return categories_present / total_categories


def detect_encoding(data: str) -> EncodingType:
    """Detect the likely encoding type of a string.

    Checks whether the string matches common encoding patterns (hex,
    base64, base32). Falls back to PLAINTEXT if no encoding matches.

    Args:
        data: Input string to analyze.

    Returns:
        The detected or most likely encoding type.
    """
    stripped = data.strip()

    if _HEX_RE.match(stripped):
        return EncodingType.HEX

    if _BASE64_RE.match(stripped) or _BASE64_URL_RE.match(stripped):
        return EncodingType.BASE64

    if _BASE32_RE.match(stripped):
        return EncodingType.BASE32

    return EncodingType.PLAINTEXT


def is_high_entropy(
    data: str,
    threshold: float | None = None,
) -> bool:
    """Check if a string has entropy above the given or auto-detected threshold.

    If no explicit threshold is provided, the threshold is determined
    automatically based on the detected encoding type.

    Args:
        data: Input string to analyze.
        threshold: Explicit entropy threshold. If None, auto-detected.

    Returns:
        True if entropy exceeds the threshold.
    """
    if not data or len(data) < 8:
        return False

    if threshold is None:
        encoding = detect_encoding(data)
        threshold = ENTROPY_THRESHOLDS[encoding]

    entropy = calculate_shannon_entropy(data)
    return entropy >= threshold


def entropy_score(data: str) -> float:
    """Calculate a normalised entropy score between 0.0 and 1.0.

    This is useful for combining with other confidence signals. The score
    is normalised against the theoretical maximum entropy for the string's
    character set.

    Args:
        data: Input string to score.

    Returns:
        Normalised entropy score, 0.0 to 1.0.
    """
    if not data or len(data) < 4:
        return 0.0

    entropy = calculate_shannon_entropy(data)
    unique_chars = len(set(data))

    if unique_chars <= 1:
        return 0.0

    max_entropy = math.log2(unique_chars)
    if max_entropy == 0:
        return 0.0

    return min(entropy / max_entropy, 1.0)
