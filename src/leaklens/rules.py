"""Built-in secret detection rules."""

from __future__ import annotations

from .models import RuleSpec, Severity

BUILTIN_RULES: list[RuleSpec] = [
    RuleSpec(
        name="aws_access_key",
        secret_type="AWS Access Key",
        pattern=r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b",
        severity=Severity.HIGH,
        confidence=0.95,
        risk="AWS access keys can grant direct API access to cloud resources.",
        remediation="Rotate this key and use IAM roles or short-lived credentials.",
    ),
    RuleSpec(
        name="aws_secret_key",
        secret_type="AWS Secret Key",
        pattern=r"(?i)(?:aws(.{0,15})?(?:secret|access).{0,10}[=:]\s*[\"']?)([A-Za-z0-9/+=]{40})",
        severity=Severity.CRITICAL,
        confidence=0.97,
        risk="AWS secret keys can allow full account compromise depending on IAM scope.",
        remediation="Revoke and rotate the key immediately, then migrate to role-based auth.",
        value_group=2,
    ),
    RuleSpec(
        name="github_token",
        secret_type="GitHub Token",
        pattern=r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",
        severity=Severity.HIGH,
        confidence=0.95,
        risk="GitHub tokens can be used to access repositories, secrets, and workflows.",
        remediation="Revoke token in GitHub settings and replace with fine-grained token scope.",
    ),
    RuleSpec(
        name="gitlab_token",
        secret_type="GitLab Token",
        pattern=r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
        severity=Severity.HIGH,
        confidence=0.94,
        risk="GitLab personal tokens can expose source code and CI/CD credentials.",
        remediation="Revoke token in GitLab and issue a minimally scoped replacement.",
    ),
    RuleSpec(
        name="slack_token",
        secret_type="Slack Token",
        pattern=r"\bxox[baprs]-[A-Za-z0-9-]{10,100}\b",
        severity=Severity.HIGH,
        confidence=0.94,
        risk="Slack tokens can expose workspace messages and app permissions.",
        remediation="Rotate the token in Slack app settings and audit workspace access logs.",
    ),
    RuleSpec(
        name="stripe_secret",
        secret_type="Stripe Secret Key",
        pattern=r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b",
        severity=Severity.CRITICAL,
        confidence=0.95,
        risk="Stripe secret keys can authorize payment and customer data operations.",
        remediation="Roll key in Stripe dashboard and reconfigure runtime secret injection.",
    ),
    RuleSpec(
        name="openai_key",
        secret_type="OpenAI API Key",
        pattern=r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        severity=Severity.HIGH,
        confidence=0.95,
        risk="Leaked OpenAI keys can consume quota and expose model usage.",
        remediation="Regenerate API key in OpenAI dashboard and use environment secrets.",
    ),
    RuleSpec(
        name="google_api_key",
        secret_type="Google API Key",
        pattern=r"\bAIza[0-9A-Za-z\-_]{35}\b",
        severity=Severity.HIGH,
        confidence=0.94,
        risk="Google API keys can enable unauthorized access and billing charges.",
        remediation="Rotate key in Google Cloud and restrict API/domain usage.",
    ),
    RuleSpec(
        name="jwt_token",
        secret_type="JWT Token",
        pattern=r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        severity=Severity.MEDIUM,
        confidence=0.84,
        risk="JWTs may allow session impersonation if still valid.",
        remediation="Invalidate active sessions and avoid storing JWTs in source code.",
    ),
    RuleSpec(
        name="ssh_private_key",
        secret_type="SSH Private Key",
        pattern=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        confidence=0.99,
        risk="Private SSH keys can grant direct infrastructure access.",
        remediation="Revoke the key from authorized hosts and replace it immediately.",
    ),
    RuleSpec(
        name="rsa_private_key",
        secret_type="RSA Private Key",
        pattern=r"-----BEGIN RSA PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        confidence=0.99,
        risk="RSA private keys compromise encrypted channels and identity trust.",
        remediation="Revoke related certificates/keys and reissue secure replacements.",
    ),
    RuleSpec(
        name="dotenv_assignment",
        secret_type=".env Secret",
        pattern=(
            r"(?i)^\s*[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|AUTH|"
            r"CREDENTIAL)[A-Z0-9_]*\s*=\s*([^#\n\r]{8,})\s*$"
        ),
        severity=Severity.MEDIUM,
        confidence=0.82,
        risk="Committed .env-style sensitive values are frequently copied into production environments.",
        remediation="Commit only placeholders and keep real values in deployment secrets.",
        value_group=1,
    ),
    RuleSpec(
        name="db_url_with_creds",
        secret_type="Database URL Credentials",
        pattern=r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/]+:[^\s@/]+@[^\s]+",
        severity=Severity.HIGH,
        confidence=0.92,
        risk="Database URLs with embedded credentials leak direct data-plane access.",
        remediation="Split credentials into env vars and assemble connection strings at runtime.",
    ),
]


def builtin_rules() -> list[RuleSpec]:
    """Return a copy of built-in rules."""
    return list(BUILTIN_RULES)


def format_rule_listing(rules: list[RuleSpec]) -> str:
    """Render rule list for CLI output."""
    lines = ["Built-in and configured rules:"]
    for rule in sorted(rules, key=lambda item: item.name):
        lines.append(
            f"- {rule.name}: type={rule.secret_type}, severity={rule.severity.value}, confidence={rule.confidence:.2f}"
        )
    return "\n".join(lines)
