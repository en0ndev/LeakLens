"""Contextual detector for suspicious secret-like assignments and usage."""

from __future__ import annotations

import re

from .entropy import shannon_entropy
from ..models import DetectionMatch, DetectorSource, Severity

SUSPICIOUS_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "auth",
    "credential",
    "apikey",
}

QUOTED_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_\-]*)\s*[:=]\s*(?P<quote>['\"])(?P<value>[^'\"\n#]{6,})(?P=quote)"
)
UNQUOTED_ENV_PATTERN = re.compile(r"(?P<name>[A-Za-z_][A-Za-z0-9_\-]*)\s*[:=]\s*(?P<value>[^\s#]{12,})\s*$")

CONNECTION_STRING_PATTERN = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/]+:[^\s@/]+@[^\s]+"
)

AUTH_CONTEXT_PATTERN = re.compile(r"(?i)\b(auth|login|security|credential|bearer|jwt|oauth|session)\b")

PLACEHOLDERS = {"changeme", "example", "sample", "test", "dummy", "password", "secret"}
NAME_SPLIT_PATTERN = re.compile(r"[^A-Za-z0-9]+")


class ContextDetector:
    """Detect secrets with heuristic context analysis."""

    def scan_line(self, file_path: str, line_number: int, line: str) -> list[DetectionMatch]:
        """Inspect line semantics for suspicious literals and credential usage."""
        del line_number
        hits: list[DetectionMatch] = []
        lowered = line.lower()
        stripped = line.strip()

        if re.match(r"^\s*(#|//|/\*|\*)", stripped):
            return []

        for match in CONNECTION_STRING_PATTERN.finditer(line):
            value = match.group(0)
            if _is_templated_connection_string(value):
                continue
            hits.append(
                DetectionMatch(
                    finding_type="Connection String Credential",
                    value=value,
                    start=match.start(0),
                    end=match.end(0),
                    source=DetectorSource.CONTEXT,
                    confidence=0.9,
                    severity=Severity.HIGH,
                    risk="Credentials embedded in connection strings leak through logs and source control.",
                    remediation=(
                        "Move user/password to env vars and construct the connection string at runtime."
                    ),
                    safer_alternative=(
                        "Use separate DB_USER/DB_PASSWORD env vars and never commit real values."
                    ),
                    autofix=(
                        "Replace literal with f\"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@...\"."
                    ),
                )
            )

        for match in QUOTED_ASSIGNMENT_PATTERN.finditer(line):
            name = match.group("name")
            value = match.group("value").strip()
            if _should_skip_assignment_value(value):
                continue
            if not _is_suspicious_name(name):
                continue

            confidence = 0.62
            severity = Severity.MEDIUM
            if len(value) > 16:
                confidence += 0.1
            if _has_diverse_chars(value):
                confidence += 0.08
            if len(value) > 28:
                severity = Severity.HIGH

            hits.append(
                DetectionMatch(
                    finding_type="Suspicious Hardcoded Credential",
                    value=value,
                    start=match.start("value"),
                    end=match.end("value"),
                    source=DetectorSource.CONTEXT,
                    confidence=min(confidence, 0.92),
                    severity=severity,
                    risk="Hardcoded credentials are often propagated to logs, forks, and artifacts.",
                    remediation="Replace literal with an environment variable and rotate if already exposed.",
                    safer_alternative=(
                        "Use os.getenv() in Python or process.env in Node with secret manager injection."
                    ),
                    autofix=_autofix_for_assignment(file_path, name),
                )
            )

        if file_path.endswith(".env"):
            for match in UNQUOTED_ENV_PATTERN.finditer(line):
                name = match.group("name")
                value = match.group("value").strip()
                if _should_skip_assignment_value(value):
                    continue
                if not _is_suspicious_name(name):
                    continue
                if len(value) < 16:
                    continue

                hits.append(
                    DetectionMatch(
                        finding_type="Suspicious Hardcoded Credential",
                        value=value,
                        start=match.start("value"),
                        end=match.end("value"),
                        source=DetectorSource.CONTEXT,
                        confidence=0.74,
                        severity=Severity.HIGH,
                        risk="Hardcoded credentials are often propagated to logs, forks, and artifacts.",
                        remediation="Replace literal with an environment variable and rotate if already exposed.",
                        safer_alternative=(
                            "Use os.getenv() in Python or process.env in Node with secret manager injection."
                        ),
                        autofix=_autofix_for_assignment(file_path, name),
                    )
                )

        if AUTH_CONTEXT_PATTERN.search(lowered):
            literals = _extract_string_literals(line)
            for value, start, end in literals:
                if len(value) < 16 or _is_placeholder(value):
                    continue
                if _should_skip_assignment_value(value):
                    continue
                if shannon_entropy(value) < 3.4:
                    continue
                if not _looks_secret_like_literal(value):
                    continue

                hits.append(
                    DetectionMatch(
                        finding_type="Auth Context Secret Literal",
                        value=value,
                        start=start,
                        end=end,
                        source=DetectorSource.CONTEXT,
                        confidence=0.65,
                        severity=Severity.MEDIUM,
                        risk="Sensitive literals near auth/security code are likely real secrets.",
                        remediation="Move this literal to secrets storage and reference by env variable.",
                        safer_alternative=(
                            "Use runtime secret injection and avoid embedding values in repository code."
                        ),
                        autofix="Replace literal with os.getenv(\"AUTH_SECRET\") and define .env.example entry.",
                    )
                )

        return hits


def _extract_string_literals(line: str) -> list[tuple[str, int, int]]:
    matches: list[tuple[str, int, int]] = []
    for pattern in (r'"([^"\n]{6,})"', r"'([^'\n]{6,})'"):
        for match in re.finditer(pattern, line):
            value = match.group(1)
            matches.append((value, match.start(1), match.end(1)))
    return matches


def _has_diverse_chars(value: str) -> bool:
    classes = sum(
        [
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        ]
    )
    return classes >= 2


def _is_suspicious_name(name: str) -> bool:
    normalized = _to_snake_case(name)
    tokens = [token for token in NAME_SPLIT_PATTERN.split(normalized) if token]
    token_set = {token.lower() for token in tokens}

    if {"api", "key"}.issubset(token_set):
        return True
    if {"private", "key"}.issubset(token_set):
        return True
    if {"access", "key"}.issubset(token_set):
        return True
    if {"secret", "key"}.issubset(token_set):
        return True
    if {"client", "secret"}.issubset(token_set):
        return True

    return any(token in SUSPICIOUS_NAMES for token in token_set)


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered in PLACEHOLDERS or lowered.startswith("example") or lowered.startswith("replace")


def _should_skip_assignment_value(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    if _is_placeholder(stripped):
        return True
    if " " in stripped:
        return True
    if lowered in {"true", "false", "null", "none"}:
        return True
    if stripped.isdigit():
        return True
    if "(" in stripped or ")" in stripped:
        return True
    if lowered.startswith(("http://", "https://", "file://")):
        return True
    if lowered.startswith(("./", "../", "/")):
        return True
    if "${" in stripped or "{{" in stripped:
        return True
    return False


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


def _looks_secret_like_literal(value: str) -> bool:
    if len(value) < 16:
        return False
    if " " in value:
        return False
    has_upper = any(char.isupper() for char in value)
    has_lower = any(char.islower() for char in value)
    has_digit = any(char.isdigit() for char in value)
    has_symbol = any(not char.isalnum() for char in value)
    score = sum([has_upper, has_lower, has_digit, has_symbol])
    return score >= 2


def _to_snake_case(name: str) -> str:
    with_boundaries = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return with_boundaries.replace("-", "_").lower()


def _autofix_for_assignment(file_path: str, name: str) -> str:
    env_name = name.upper().replace("-", "_")
    if file_path.endswith(".py"):
        return f"Use os.getenv(\"{env_name}\") instead of hardcoding this value."
    if file_path.endswith((".js", ".ts")):
        return f"Use process.env.{env_name} instead of hardcoding this value."
    return f"Replace literal with environment variable {env_name}."
