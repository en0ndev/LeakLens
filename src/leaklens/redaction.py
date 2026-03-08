"""Secret redaction helpers for safe terminal and JSON output."""

from __future__ import annotations

import re

_PREFIX_RULES: list[tuple[re.Pattern[str], int, int]] = [
    (re.compile(r"^gh[pousr]_"), 4, 4),
    (re.compile(r"^glpat-"), 6, 4),
    (re.compile(r"^sk-(?:proj-)?"), 3, 3),
    (re.compile(r"^xox[baprs]-"), 5, 3),
    (re.compile(r"^AIza"), 4, 4),
    (re.compile(r"^(AKIA|ASIA|AGPA|AIDA|AROA)"), 4, 4),
]


def mask_secret(value: str) -> str:
    """Mask a secret while preserving a minimal recognizable prefix/suffix."""
    if not value:
        return ""

    for pattern, keep_prefix, keep_suffix in _PREFIX_RULES:
        if pattern.search(value):
            return _mask(value, keep_prefix, keep_suffix)

    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 8:
        return value[0] + ("*" * (len(value) - 2)) + value[-1]

    return _mask(value, 4, 4)


def mask_in_line(line: str, secret: str) -> str:
    """Replace first secret occurrence in a line with masked content."""
    if not secret:
        return line.strip()

    snippet = line.strip()
    if secret in snippet:
        snippet = snippet.replace(secret, mask_secret(secret), 1)

    if len(snippet) > 220:
        snippet = snippet[:217] + "..."
    return snippet


def _mask(value: str, keep_prefix: int, keep_suffix: int) -> str:
    if len(value) <= keep_prefix + keep_suffix:
        return "*" * len(value)
    middle = "*" * (len(value) - keep_prefix - keep_suffix)
    return value[:keep_prefix] + middle + value[-keep_suffix:]
