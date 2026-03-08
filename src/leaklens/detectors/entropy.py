"""Entropy-based detector implementation."""

from __future__ import annotations

import math
import re
from collections import Counter

from ..models import DetectionMatch, DetectorSource, Severity

ASSIGNMENT_PATTERN = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_-]{1,})\s*[:=]\s*(?P<value>[A-Za-z0-9_+/=.-]{16,})"
)
QUOTED_PATTERN = re.compile(r"""(?P<quote>['"])(?P<value>[A-Za-z0-9_+/=:.~-]{16,})(?P=quote)""")
TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9])(?P<value>[A-Za-z0-9_+./-]{20,}={0,2})(?![A-Za-z0-9])")
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE
)
HEX_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.IGNORECASE)


class EntropyDetector:
    """Finds candidate secrets using Shannon entropy."""

    def __init__(self, threshold: float) -> None:
        self.threshold = threshold

    def scan_line(self, file_path: str, line_number: int, line: str) -> list[DetectionMatch]:
        """Evaluate high-entropy candidate tokens in one line."""
        del file_path, line_number
        hits: list[DetectionMatch] = []

        for value, start, end in _extract_candidates(line):
            if _skip_candidate(value):
                continue

            entropy = shannon_entropy(value)
            if entropy < self.threshold:
                continue

            confidence = min(0.92, 0.48 + (entropy - self.threshold) * 0.18)
            severity = Severity.MEDIUM if confidence < 0.8 else Severity.HIGH

            hits.append(
                DetectionMatch(
                    finding_type="High Entropy Secret",
                    value=value,
                    start=start,
                    end=end,
                    source=DetectorSource.ENTROPY,
                    confidence=confidence,
                    severity=severity,
                    risk=(
                        "High-entropy literals often indicate API keys, access tokens, or other credentials."
                    ),
                    remediation=(
                        "Move the value to managed secrets and rotate it if exposure is possible."
                    ),
                    safer_alternative=(
                        "Use environment variables and inject secrets via CI/CD or secret manager."
                    ),
                    autofix="Replace literal with os.getenv(\"SECRET_VALUE\") and document in .env.example.",
                )
            )

        return hits


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy for a string."""
    if not value:
        return 0.0

    frequencies = Counter(value)
    total = len(value)
    entropy = 0.0

    for count in frequencies.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def _extract_candidates(line: str) -> list[tuple[str, int, int]]:
    seen: set[tuple[int, int]] = set()
    candidates: list[tuple[str, int, int]] = []

    for pattern, group in (
        (QUOTED_PATTERN, "value"),
        (ASSIGNMENT_PATTERN, "value"),
        (TOKEN_PATTERN, "value"),
    ):
        for match in pattern.finditer(line):
            start = match.start(group)
            end = match.end(group)
            span = (start, end)
            if span in seen:
                continue
            seen.add(span)
            candidates.append((match.group(group), start, end))

    return candidates


def _skip_candidate(value: str) -> bool:
    if len(value) < 16:
        return True
    if value.startswith(("http://", "https://")):
        return True
    if value.startswith(("./", "../", "/")):
        return True
    if "@" in value and "." in value and "/" in value:
        return True
    if "${" in value or "{{" in value:
        return True
    if UUID_PATTERN.match(value):
        return True
    if HEX_DIGEST_PATTERN.match(value):
        return True
    if "=" in value[:-2]:
        return True
    if "/" in value and value.count("/") >= 2 and "." in value:
        return True
    if value.isdigit():
        return True
    if len(set(value)) <= 3:
        return True

    classes = sum(
        [
            any(char.islower() for char in value),
            any(char.isupper() for char in value),
            any(char.isdigit() for char in value),
            any(not char.isalnum() for char in value),
        ]
    )
    return classes < 3
