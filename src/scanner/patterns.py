"""Secret detection patterns registry.

Contains all built-in secret patterns for scanning. Each pattern is a
`SecretPattern` dataclass with a compiled regex, severity, confidence score,
and false positive filters.

Architecture Decision:
    Patterns are stored in a `PatternRegistry` that allows runtime registration of
    custom patterns. This enables users to extend the scanner without modifying core code.
"""

from __future__ import annotations

import re
from typing import Iterator

from scanner.models import SecretPattern, Severity

# ---------------------------------------------------------------------------
# Common false-positive patterns reused across multiple secret types
# ---------------------------------------------------------------------------

_PLACEHOLDER_FP: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^(?:example|sample|test|dummy|fake|mock|placeholder|changeme|replace)(?:[_\-\s]|$)",
        r"^(?:xxx+|yyy+|zzz+|aaa+|000+|1234|your[_-])",
        r"(?:TODO|FIXME|REPLACE|INSERT|FILL)",
        r"\<[^>]+\>",  # Template syntax: <YOUR_KEY>
        r"\{\{[^}]+\}\}",  # Mustache/Jinja: {{API_KEY}}
        r"\$\{[^}]+\}",  # Shell/envsubst: ${API_KEY}
        r"%\([^)]+\)",  # Python format: %(api_key)s
    ]
)


class PatternRegistry:
    """Registry for secret detection patterns.

    Manages a collection of `SecretPattern` instances and provides lookup
    and filtering capabilities. Thread-safe for read operations after
    initialization.

    Example:
        registry = PatternRegistry()
        registry.register_defaults()
        for pattern in registry.get_by_severity(Severity.CRITICAL):
            print(pattern.name)
    """

    def __init__(self) -> None:
        self._patterns: dict[str, SecretPattern] = {}

    def register(self, pattern: SecretPattern) -> None:
        """Register a new secret pattern.

        Args:
            pattern: The pattern to register.

        Raises:
            ValueError: If a pattern with the same ID already exists.
        """
        if pattern.id in self._patterns:
            raise ValueError(
                f"Pattern with id '{pattern.id}' is already registered. "
                f"Use a unique id for each pattern."
            )
        self._patterns[pattern.id] = pattern

    def get_all(self) -> list[SecretPattern]:
        """Return all registered patterns.

        Returns:
            List of all patterns, ordered by severity (highest first).
        """
        return sorted(self._patterns.values(), key=lambda p: p.severity, reverse=True)

    def get_by_severity(self, min_severity: Severity) -> list[SecretPattern]:
        """Return patterns at or above the given severity.

        Args:
            min_severity: Minimum severity threshold.

        Returns:
            Filtered and sorted list of patterns.
        """
        return [p for p in self.get_all() if p.severity >= min_severity]

    def get_by_id(self, pattern_id: str) -> SecretPattern | None:
        """Look up a single pattern by its ID.

        Args:
            pattern_id: The unique pattern identifier.

        Returns:
            The pattern, or None if not found.
        """
        return self._patterns.get(pattern_id)

    def __len__(self) -> int:
        return len(self._patterns)

    def __iter__(self) -> Iterator[SecretPattern]:
        return iter(self.get_all())

    def __contains__(self, pattern_id: str) -> bool:
        return pattern_id in self._patterns


# ---------------------------------------------------------------------------
# DEFAULT PATTERNS — Built-in secret detectors
# ---------------------------------------------------------------------------

def _build_default_patterns() -> list[SecretPattern]:
    """Build and return all default secret patterns.

    Returns:
        List of built-in SecretPattern definitions.
    """
    return [
        # ===================================================================
        # CRITICAL — Direct financial / data-breach risk
        # ===================================================================
        SecretPattern(
            id="aws-access-key",
            name="AWS Access Key",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)"
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="AWS Access Key ID beginning with AKIA.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP + (
                re.compile(r"AKIAIOSFODNN7EXAMPLE", re.IGNORECASE),
            ),
            entropy_threshold=3.0,
        ),
        SecretPattern(
            id="aws-secret-key",
            name="AWS Secret Access Key",
            pattern=re.compile(
                r"(?:aws_secret_access_key|aws_secret_key|secret_key)"
                r"""[\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            confidence=0.90,
            description="AWS Secret Access Key (40-character base64).",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=4.0,
        ),
        SecretPattern(
            id="github-pat",
            name="GitHub Personal Access Token",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_])(ghp_[A-Za-z0-9]{36,255})(?:[^A-Za-z0-9_]|$)"
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="GitHub Personal Access Token (ghp_ prefix).",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="github-oauth",
            name="GitHub OAuth Access Token",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_])(gho_[A-Za-z0-9]{36,255})(?:[^A-Za-z0-9_]|$)"
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="GitHub OAuth Access Token (gho_ prefix).",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="github-app-token",
            name="GitHub App Token",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_])(ghs_[A-Za-z0-9]{36,255})(?:[^A-Za-z0-9_]|$)"
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="GitHub App Installation Token (ghs_ prefix).",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="stripe-secret-key",
            name="Stripe Secret Key",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_])(sk_live_[A-Za-z0-9]{24,99})(?:[^A-Za-z0-9_]|$)"
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Stripe live secret API key.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="stripe-restricted-key",
            name="Stripe Restricted Key",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_])(rk_live_[A-Za-z0-9]{24,99})(?:[^A-Za-z0-9_]|$)"
            ),
            severity=Severity.CRITICAL,
            confidence=0.95,
            description="Stripe live restricted API key.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="private-ssh-key",
            name="Private SSH Key",
            pattern=re.compile(
                r"-----BEGIN\s(?:RSA|DSA|EC|OPENSSH|PGP)\sPRIVATE\sKEY-----"
            ),
            severity=Severity.CRITICAL,
            confidence=0.99,
            description="Private SSH/PGP key header detected.",
            secret_group=0,
        ),
        SecretPattern(
            id="postgres-connection-string",
            name="PostgreSQL Connection String",
            pattern=re.compile(
                r"postgres(?:ql)?://[^\s'\"]{8,256}",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            confidence=0.85,
            description="PostgreSQL connection URI with credentials.",
            secret_group=0,
            false_positive_patterns=_PLACEHOLDER_FP + (
                re.compile(r"localhost|127\.0\.0\.1|example\.com|postgres://user:pass@"),
            ),
        ),
        SecretPattern(
            id="mysql-connection-string",
            name="MySQL Connection String",
            pattern=re.compile(
                r"mysql://[^\s'\"]{8,256}",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            confidence=0.85,
            description="MySQL connection URI with credentials.",
            secret_group=0,
            false_positive_patterns=_PLACEHOLDER_FP + (
                re.compile(r"localhost|127\.0\.0\.1|example\.com|mysql://user:pass@"),
            ),
        ),

        # ===================================================================
        # HIGH — Significant service access
        # ===================================================================
        SecretPattern(
            id="openai-api-key",
            name="OpenAI API Key",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_-])(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})"
                r"(?:[^A-Za-z0-9_-]|$)"
            ),
            severity=Severity.HIGH,
            confidence=0.95,
            description="OpenAI API key with standard format.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="openai-api-key-v2",
            name="OpenAI API Key (Project)",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_-])(sk-proj-[A-Za-z0-9_-]{40,255})"
                r"(?:[^A-Za-z0-9_-]|$)"
            ),
            severity=Severity.HIGH,
            confidence=0.90,
            description="OpenAI project-scoped API key.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="google-api-key",
            name="Google API Key",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_])(AIza[0-9A-Za-z_-]{35})(?:[^A-Za-z0-9_-]|$)"
            ),
            severity=Severity.HIGH,
            confidence=0.85,
            description="Google API key starting with AIza.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="slack-bot-token",
            name="Slack Bot Token",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_-])(xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24})"
                r"(?:[^A-Za-z0-9_-]|$)"
            ),
            severity=Severity.HIGH,
            confidence=0.95,
            description="Slack bot user OAuth token.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="slack-user-token",
            name="Slack User Token",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_-])(xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32})"
                r"(?:[^A-Za-z0-9_-]|$)"
            ),
            severity=Severity.HIGH,
            confidence=0.95,
            description="Slack user OAuth token.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="slack-webhook",
            name="Slack Webhook URL",
            pattern=re.compile(
                r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"
            ),
            severity=Severity.HIGH,
            confidence=0.95,
            description="Slack incoming webhook URL.",
            secret_group=0,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="jwt-token",
            name="JWT Token",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_-])"
                r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
                r"(?:[^A-Za-z0-9_-]|$)"
            ),
            severity=Severity.HIGH,
            confidence=0.80,
            description="JSON Web Token (JWT) with header.payload.signature.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=3.5,
        ),
        SecretPattern(
            id="sendgrid-api-key",
            name="SendGrid API Key",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_.])(SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,})"
                r"(?:[^A-Za-z0-9_.-]|$)"
            ),
            severity=Severity.HIGH,
            confidence=0.95,
            description="SendGrid API key (SG. prefix).",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="basic-auth-url",
            name="Basic Auth in URL",
            pattern=re.compile(
                r"https?://[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
            ),
            severity=Severity.HIGH,
            confidence=0.80,
            description="HTTP(S) URL with embedded username:password.",
            secret_group=0,
            false_positive_patterns=_PLACEHOLDER_FP + (
                re.compile(r"user:pass|username:password|admin:admin"),
                re.compile(r"example\.com|localhost"),
            ),
        ),
        SecretPattern(
            id="npm-token",
            name="NPM Access Token",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?:[^A-Za-z0-9_]|$)"
            ),
            severity=Severity.HIGH,
            confidence=0.95,
            description="NPM access token.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),
        SecretPattern(
            id="pypi-token",
            name="PyPI API Token",
            pattern=re.compile(
                r"(?:^|[^A-Za-z0-9_])(pypi-[A-Za-z0-9_-]{50,})(?:[^A-Za-z0-9_-]|$)"
            ),
            severity=Severity.HIGH,
            confidence=0.95,
            description="PyPI API token.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
        ),

        # ===================================================================
        # MEDIUM — Limited access / moderate risk
        # ===================================================================
        SecretPattern(
            id="azure-storage-key",
            name="Azure Storage Account Key",
            pattern=re.compile(
                r"(?:AccountKey|account_key|storage_key)"
                r"""[\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{86,88}==)['"]?""",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            confidence=0.80,
            description="Azure Storage account key (base64, 88 chars).",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=4.0,
        ),
        SecretPattern(
            id="gcp-service-account",
            name="GCP Service Account Key",
            pattern=re.compile(
                r'"type"\s*:\s*"service_account"'
            ),
            severity=Severity.MEDIUM,
            confidence=0.85,
            description="Google Cloud service account JSON key file marker.",
            secret_group=0,
        ),
        SecretPattern(
            id="docker-registry-auth",
            name="Docker Registry Auth",
            pattern=re.compile(
                r'"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"'
            ),
            severity=Severity.MEDIUM,
            confidence=0.70,
            description="Docker registry base64-encoded auth token.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=3.5,
        ),
        SecretPattern(
            id="generic-api-key-assignment",
            name="Generic API Key Assignment",
            pattern=re.compile(
                r"(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)"
                r"""[\s]*[=:]\s*['"]([A-Za-z0-9_\-/.+=]{16,128})['"]""",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            confidence=0.60,
            description="Generic API key/secret/token assignment.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=3.0,
        ),
        SecretPattern(
            id="generic-password-assignment",
            name="Generic Password Assignment",
            pattern=re.compile(
                r"(?:password|passwd|pwd|pass)"
                r"""[\s]*[=:]\s*['"]([^'"]{8,128})['"]""",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            confidence=0.55,
            description="Password assigned to a variable or config key.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP + (
                re.compile(r"^\*+$"),  # Masked: ****
                re.compile(r"^password$", re.IGNORECASE),
            ),
            entropy_threshold=2.5,
        ),
        SecretPattern(
            id="generic-secret-assignment",
            name="Generic Secret Assignment",
            pattern=re.compile(
                r"(?:secret|secret[_-]?key|client[_-]?secret)"
                r"""[\s]*[=:]\s*['"]([A-Za-z0-9_\-/.+=]{16,128})['"]""",
                re.IGNORECASE,
            ),
            severity=Severity.MEDIUM,
            confidence=0.55,
            description="Generic secret/client_secret assignment.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=3.0,
        ),
        SecretPattern(
            id="private-key-generic",
            name="Generic Private Key",
            pattern=re.compile(
                r"-----BEGIN\s(?:PRIVATE\sKEY|ENCRYPTED\sPRIVATE\sKEY)-----"
            ),
            severity=Severity.MEDIUM,
            confidence=0.95,
            description="Generic PKCS#8 private key header.",
            secret_group=0,
        ),

        # ===================================================================
        # TURKISH PROVIDERS — Unique value-add
        # ===================================================================
        SecretPattern(
            id="iyzico-api-key",
            name="İyzico API Key",
            pattern=re.compile(
                r"(?:iyzico|iyzipay)[\s_-]*(?:api)?[\s_-]*(?:key|secret)"
                r"""[\s]*[=:]\s*['"]([A-Za-z0-9]{10,64})['"]""",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            confidence=0.85,
            description="İyzico payment gateway API key.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=3.0,
        ),
        SecretPattern(
            id="iyzico-secret-key",
            name="İyzico Secret Key",
            pattern=re.compile(
                r"(?:iyzico|iyzipay)[\s_-]*secret[\s_-]*(?:key)?"
                r"""[\s]*[=:]\s*['"]([A-Za-z0-9]{10,64})['"]""",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            confidence=0.85,
            description="İyzico payment gateway secret key.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=3.0,
        ),
        SecretPattern(
            id="paytr-merchant-key",
            name="PayTR Merchant Key",
            pattern=re.compile(
                r"(?:paytr)[\s_-]*(?:merchant)?[\s_-]*(?:key|salt|secret)"
                r"""[\s]*[=:]\s*['"]([A-Za-z0-9]{8,64})['"]""",
                re.IGNORECASE,
            ),
            severity=Severity.CRITICAL,
            confidence=0.85,
            description="PayTR payment gateway merchant key/salt.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=2.5,
        ),
        SecretPattern(
            id="turktelekom-cloud-key",
            name="Türk Telekom Cloud Key",
            pattern=re.compile(
                r"(?:turk\s?telekom|bulut|ttcloud)"
                r"[\s_-]*(?:api)?[\s_-]*(?:key|secret|token)"
                r"""[\s]*[=:]\s*['"]([A-Za-z0-9_\-]{16,128})['"]""",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            confidence=0.75,
            description="Türk Telekom Cloud API credentials.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=3.0,
        ),
        SecretPattern(
            id="edevlet-api-key",
            name="e-Devlet API Key",
            pattern=re.compile(
                r"(?:e[\s_-]*devlet|turkiye\.gov|edevlet)"
                r"[\s_-]*(?:api)?[\s_-]*(?:key|secret|token)"
                r"""[\s]*[=:]\s*['"]([A-Za-z0-9_\-]{16,128})['"]""",
                re.IGNORECASE,
            ),
            severity=Severity.HIGH,
            confidence=0.75,
            description="Turkish Government (e-Devlet) API key.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=3.0,
        ),

        # ===================================================================
        # LOW — Informational / weak signals
        # ===================================================================
        SecretPattern(
            id="env-file-secret",
            name="Dotenv Secret Value",
            pattern=re.compile(
                r"^(?:SECRET|TOKEN|AUTH|CREDENTIAL|PRIVATE)[A-Z_]*"
                r"""=\s*['"]?([A-Za-z0-9_\-/.+=]{8,256})['"]?\s*$""",
                re.MULTILINE,
            ),
            severity=Severity.LOW,
            confidence=0.50,
            description="Suspicious value in .env-style KEY=VALUE assignment.",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP,
            entropy_threshold=3.0,
        ),
        SecretPattern(
            id="high-entropy-hex",
            name="High Entropy Hex String",
            pattern=re.compile(
                r"""['"]([0-9a-f]{32,64})['"]""",
                re.IGNORECASE,
            ),
            severity=Severity.LOW,
            confidence=0.40,
            description="Long hex-encoded string (potential secret/hash).",
            secret_group=1,
            false_positive_patterns=_PLACEHOLDER_FP + (
                re.compile(r"(?:hash|checksum|sha|md5|digest)", re.IGNORECASE),
            ),
            entropy_threshold=3.5,
        ),
    ]


def create_default_registry() -> PatternRegistry:
    """Create and return a PatternRegistry populated with all default patterns.

    Returns:
        A PatternRegistry containing all built-in secret detection patterns.
    """
    registry = PatternRegistry()
    for pattern in _build_default_patterns():
        registry.register(pattern)
    return registry
