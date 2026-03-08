"""Regex-based detector implementation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

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

        for compiled in self._rules:
            if compiled.spec.name == "dotenv_assignment" and not file_name.startswith(".env"):
                continue
            for match in compiled.pattern.finditer(line):
                value, start, end = _extract_value(match, compiled.spec.value_group)
                if not value:
                    continue
                if compiled.spec.name == "dotenv_assignment" and _is_placeholder_value(value):
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
