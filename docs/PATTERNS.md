# Supported Patterns

## Built-in Patterns Overview

Dotenv Secrets Scanner ships with **30+ built-in patterns** for detecting secrets across various providers and services.

## Pattern Details

### CRITICAL Severity

| ID | Name | Example Pattern | Entropy Check |
|----|------|-----------------|---------------|
| `aws-access-key` | AWS Access Key | `AKIA[0-9A-Z]{16}` | ✅ (3.0) |
| `aws-secret-key` | AWS Secret Key | `aws_secret_key = '[40 chars]'` | ✅ (4.0) |
| `github-pat` | GitHub PAT | `ghp_[A-Za-z0-9]{36+}` | ❌ |
| `github-oauth` | GitHub OAuth | `gho_[A-Za-z0-9]{36+}` | ❌ |
| `github-app-token` | GitHub App | `ghs_[A-Za-z0-9]{36+}` | ❌ |
| `stripe-secret-key` | Stripe Secret | `sk_live_[A-Za-z0-9]{24+}` | ❌ |
| `stripe-restricted-key` | Stripe Restricted | `rk_live_[A-Za-z0-9]{24+}` | ❌ |
| `private-ssh-key` | SSH Private Key | `-----BEGIN RSA PRIV KEY-----` | ❌ |
| `postgres-connection-string` | PostgreSQL URI | `postgres://user:pass@host` | ❌ |
| `mysql-connection-string` | MySQL URI | `mysql://user:pass@host` | ❌ |
| `iyzico-api-key` | İyzico API Key | `iyzico_api_key = '[value]'` | ✅ (3.0) |
| `iyzico-secret-key` | İyzico Secret | `iyzico_secret_key = '[value]'` | ✅ (3.0) |
| `paytr-merchant-key` | PayTR Key | `paytr_merchant_key = '[value]'` | ✅ (2.5) |

### HIGH Severity

| ID | Name | Example Pattern | Entropy Check |
|----|------|-----------------|---------------|
| `openai-api-key` | OpenAI API Key | `sk-[...]T3BlbkFJ[...]` | ❌ |
| `openai-api-key-v2` | OpenAI Project Key | `sk-proj-[A-Za-z0-9_-]{40+}` | ❌ |
| `google-api-key` | Google API Key | `AIza[0-9A-Za-z_-]{35}` | ❌ |
| `slack-bot-token` | Slack Bot Token | `xoxb-[nums]-[nums]-[chars]` | ❌ |
| `slack-user-token` | Slack User Token | `xoxp-[nums]-[nums]-[chars]` | ❌ |
| `slack-webhook` | Slack Webhook | `https://hooks.slack.com/...` | ❌ |
| `jwt-token` | JWT Token | `eyJ...eyJ...` | ✅ (3.5) |
| `sendgrid-api-key` | SendGrid API Key | `SG.[chars].[chars]` | ❌ |
| `basic-auth-url` | Basic Auth URL | `https://user:pass@host` | ❌ |
| `npm-token` | NPM Token | `npm_[A-Za-z0-9]{36}` | ❌ |
| `pypi-token` | PyPI Token | `pypi-[A-Za-z0-9_-]{50+}` | ❌ |
| `turktelekom-cloud-key` | Türk Telekom Cloud | `turktelekom_api_key = '...'` | ✅ (3.0) |
| `edevlet-api-key` | e-Devlet API Key | `edevlet_api_key = '...'` | ✅ (3.0) |

### MEDIUM Severity

| ID | Name | Entropy Check |
|----|------|---------------|
| `azure-storage-key` | Azure Storage Key | ✅ (4.0) |
| `gcp-service-account` | GCP Service Account | ❌ |
| `docker-registry-auth` | Docker Registry Auth | ✅ (3.5) |
| `generic-api-key-assignment` | Generic API Key | ✅ (3.0) |
| `generic-password-assignment` | Generic Password | ✅ (2.5) |
| `generic-secret-assignment` | Generic Secret | ✅ (3.0) |
| `private-key-generic` | Generic Private Key | ❌ |

### LOW Severity

| ID | Name | Entropy Check |
|----|------|---------------|
| `env-file-secret` | Dotenv Secret Value | ✅ (3.0) |
| `high-entropy-hex` | High Entropy Hex | ✅ (3.5) |

## Adding Custom Patterns

Create a `.secretscan.yml` and add custom regex patterns:

```yaml
custom_patterns:
  - id: "my-internal-token"
    name: "Internal Service Token"
    pattern: "MYTOKEN_[A-Za-z0-9]{32}"
    severity: HIGH
    confidence: 0.90
    description: "Internal service authentication token."
```

## False Positive Handling

Each pattern includes built-in false positive filters. Common filtered values:
- Placeholder: `YOUR_API_KEY`, `changeme`, `replace-me`
- Template syntax: `{{ API_KEY }}`, `${API_KEY}`, `<YOUR_KEY>`
- Documentation examples: `AKIAIOSFODNN7EXAMPLE`
- Test/mock values: `test_key`, `mock_secret`, `dummy_token`

To suppress specific false positives, use `.secretsignore`.
