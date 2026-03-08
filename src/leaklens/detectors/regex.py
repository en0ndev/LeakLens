"""Regex-based detector implementation."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .entropy import shannon_entropy
from ..models import DetectionMatch, DetectorSource, RuleSpec

SAFE_ALT = (
    "Move this secret into environment variables or a secret manager such as AWS Secrets Manager, "
    "HashiCorp Vault, or Doppler."
)


@dataclass(frozen=True)
class _CompiledRule:
    spec: RuleSpec
    pattern: re.Pattern[str]


class RegexDetector:
    """Detects secrets using curated and custom regex patterns."""

    def __init__(self, rules: list[RuleSpec]) -> None:
        self._rules: list[_CompiledRule] = []
        for rule in rules:
            try:
                compiled = re.compile(rule.pattern)
            except re.error:
                continue
            self._rules.append(_CompiledRule(spec=rule, pattern=compiled))

    def scan_line(self, file_path: str, line_number: int, line: str) -> list[DetectionMatch]:
        """Run all regex rules against a single line."""
        del line_number
        hits: list[DetectionMatch] = []
        file_name = Path(file_path).name
        line_lower = line.lower()

        for compiled in self._rules:
            if compiled.spec.name == "dotenv_assignment" and not file_name.startswith(".env"):
                continue
            for match in compiled.pattern.finditer(line):
                value, start, end = _extract_value(match, compiled.spec.value_group)
                if not value:
                    continue
                if compiled.spec.name == "dotenv_assignment" and _is_placeholder_value(value):
                    continue
                if not _passes_rule_heuristics(compiled.spec.name, value, line, line_lower):
                    continue
                hits.append(
                    DetectionMatch(
                        finding_type=compiled.spec.secret_type,
                        value=value,
                        start=start,
                        end=end,
                        source=DetectorSource.REGEX,
                        confidence=compiled.spec.confidence,
                        severity=compiled.spec.severity,
                        risk=compiled.spec.risk,
                        remediation=compiled.spec.remediation,
                        safer_alternative=SAFE_ALT,
                        autofix=_build_autofix(compiled.spec.secret_type, line),
                    )
                )

        return hits


def _extract_value(match: re.Match[str], value_group: int) -> tuple[str, int, int]:
    if value_group == 0:
        return match.group(0), match.start(0), match.end(0)

    try:
        value = match.group(value_group)
        if value is None:
            return "", 0, 0
        return value, match.start(value_group), match.end(value_group)
    except IndexError:
        return "", 0, 0


def _build_autofix(secret_type: str, line: str) -> str:
    line_lower = line.lower()
    if "api" in line_lower or "token" in line_lower:
        return "Replace the literal with os.getenv(\"API_KEY\") and define it in runtime secrets."
    if "postgres://" in line_lower or "mysql://" in line_lower:
        return (
            "Move DB_USER, DB_PASSWORD, DB_HOST, and DB_NAME into env vars and build the URL at runtime."
        )
    if "password" in line_lower:
        return "Replace hardcoded password with os.getenv(\"PASSWORD\") and rotate compromised credentials."
    return f"Replace hardcoded {secret_type} value with a runtime environment lookup."


def _is_placeholder_value(value: str) -> bool:
    lowered = value.strip().lower()
    placeholders = {
        "changeme",
        "example",
        "sample",
        "dummy",
        "test",
        "none",
        "null",
    }
    return lowered in placeholders or lowered.startswith("example")


def _passes_rule_heuristics(rule_name: str, value: str, line: str, line_lower: str) -> bool:
    normalized = value.strip()
    if not normalized:
        return False
    if _contains_placeholder_markers(normalized):
        return False

    if rule_name == "aws_access_key":
        if len(normalized) != 20:
            return False
        if normalized.upper().endswith("EXAMPLE"):
            return False
        return _has_any_keyword(line_lower, {"aws", "access_key", "secret_key", "iam", "akia", "asia"})

    if rule_name == "aws_secret_key":
        if len(normalized) != 40:
            return False
        return shannon_entropy(normalized) >= 3.4

    if rule_name == "github_token":
        if len(normalized) < 40:
            return False
        if not _has_any_keyword(
            line_lower,
            {"github", "token", "authorization", "bearer", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
        ):
            return False
        return shannon_entropy(_strip_prefix(normalized)) >= 3.2

    if rule_name == "stripe_secret":
        if len(normalized) < 24:
            return False
        if not _has_any_keyword(line_lower, {"stripe", "sk_live_", "sk_test_", "secret", "token", "api_key"}):
            return False
        return shannon_entropy(_strip_prefix(normalized)) >= 3.1

    if rule_name == "slack_token":
        if len(normalized) < 20 or normalized.count("-") < 2:
            return False
        if not _has_any_keyword(line_lower, {"slack", "xox", "token", "oauth", "bot", "webhook"}):
            return False
        return shannon_entropy(_strip_prefix(normalized)) >= 3.0

    if rule_name == "jwt_token":
        if len(normalized) < 80:
            return False
        if not _has_any_keyword(line_lower, {"jwt", "bearer", "authorization", "id_token", "access_token", "token"}):
            return False
        if not _looks_like_jwt_header(normalized):
            return False
        parts = normalized.split(".")
        if len(parts) != 3:
            return False
        return shannon_entropy(parts[1] + parts[2]) >= 3.2

    if rule_name == "ssh_private_key":
        marker = "-----BEGIN OPENSSH PRIVATE KEY-----"
        return _is_unquoted_marker_line(line, marker)

    if rule_name == "rsa_private_key":
        marker = "-----BEGIN RSA PRIVATE KEY-----"
        return _is_unquoted_marker_line(line, marker)

    if rule_name == "db_url_with_creds":
        return not _is_templated_connection_string(normalized)

    return True


def _strip_prefix(value: str) -> str:
    if "_" in value:
        return value.split("_", 1)[1]
    if "-" in value:
        return value.split("-", 1)[1]
    return value


def _has_any_keyword(line_lower: str, keywords: set[str]) -> bool:
    return any(keyword in line_lower for keyword in keywords)


def _contains_placeholder_markers(value: str) -> bool:
    lowered = value.lower()
    markers = {
        "example",
        "placeholder",
        "dummy",
        "changeme",
        "replace_me",
        "your_token_here",
        "your-key",
        "fake",
        "testtoken",
        "redacted",
    }
    return any(marker in lowered for marker in markers)


def _is_unquoted_marker_line(line: str, marker: str) -> bool:
    stripped = line.strip()
    if not stripped.startswith(marker):
        return False
    if stripped != marker:
        return False
    return '"' not in stripped and "'" not in stripped


def _looks_like_jwt_header(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    decoded = _decode_base64url(parts[0])
    if decoded is None:
        return False
    try:
        payload = json.loads(decoded)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    return "alg" in payload or "typ" in payload


def _is_templated_connection_string(value: str) -> bool:
    lowered = value.lower()
    if "${" in value or "{{" in value or "{" in value or "}" in value:
        return True
    if "<" in value or ">" in value or "..." in value:
        return True
    if "os.getenv(" in lowered or "process.env" in lowered:
        return True
    if "example" in lowered or "placeholder" in lowered:
        return True
    return False


def _decode_base64url(segment: str) -> str | None:
    padding = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + padding)
    except (ValueError, TypeError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
