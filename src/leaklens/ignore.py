"""Ignore and allowlist logic for paths and secrets."""

from __future__ import annotations

import re
from fnmatch import fnmatch
from pathlib import Path


class IgnoreMatcher:
    """Matches ignored paths and allowlisted values."""

    def __init__(
        self,
        root: Path,
        path_patterns: list[str] | None = None,
        allowlist_values: set[str] | None = None,
        allowlist_patterns: list[str] | None = None,
    ) -> None:
        self.root = root
        self.path_patterns = path_patterns or []
        self.allowlist_values = allowlist_values or set()
        self.allowlist_patterns: list[re.Pattern[str]] = []

        for pattern in allowlist_patterns or []:
            try:
                self.allowlist_patterns.append(re.compile(pattern))
            except re.error:
                continue

    @classmethod
    def from_files(
        cls,
        root: Path,
        config_ignored_paths: list[str],
        allowlist_values: set[str],
        allowlist_patterns: list[str],
    ) -> "IgnoreMatcher":
        """Create matcher by merging config patterns and ignore files."""
        file_patterns = read_ignore_file(root / ".leaklensignore")
        legacy_patterns = read_ignore_file(root / ".aicredleakignore")
        merged_patterns = sorted(set(config_ignored_paths + file_patterns + legacy_patterns))
        return cls(
            root=root,
            path_patterns=merged_patterns,
            allowlist_values=allowlist_values,
            allowlist_patterns=allowlist_patterns,
        )

    def should_ignore_path(self, path: Path) -> bool:
        """Return True when file path matches ignore patterns."""
        try:
            relative = path.resolve().relative_to(self.root.resolve())
        except ValueError:
            relative = path

        candidate = relative.as_posix()
        for pattern in self.path_patterns:
            if fnmatch(candidate, pattern) or fnmatch(path.name, pattern):
                return True
        return False

    def is_allowlisted(self, value: str) -> bool:
        """Return True if value is allowed by exact or regex allowlist."""
        if value in self.allowlist_values:
            return True
        return any(pattern.search(value) for pattern in self.allowlist_patterns)


INLINE_IGNORE_MARKERS = {"leaklens:ignore", "aicredleak:ignore", "credguard:ignore"}


def has_inline_ignore(line: str, marker: str) -> bool:
    """Check if a line contains a valid inline ignore marker."""
    lowered = line.lower()
    if marker.lower() in lowered:
        return True
    return any(token in lowered for token in INLINE_IGNORE_MARKERS)


def read_ignore_file(path: Path) -> list[str]:
    """Read ignore patterns from file."""
    if not path.exists():
        return []

    patterns: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        normalized = line.strip()
        if not normalized or normalized.startswith("#"):
            continue
        patterns.append(normalized)
    return patterns
