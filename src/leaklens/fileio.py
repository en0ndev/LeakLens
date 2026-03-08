"""Filesystem helpers for candidate discovery and filtering."""

from __future__ import annotations

import os
from pathlib import Path

from .config import LeakLensConfig
from .ignore import IgnoreMatcher


def discover_files(target: Path, config: LeakLensConfig, ignore: IgnoreMatcher) -> list[Path]:
    """Discover text files that should be scanned."""
    candidate = target.resolve()
    if candidate.is_file():
        if _scan_allowed(candidate, config, ignore):
            return [candidate]
        return []

    discovered: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(candidate):
        current_dir = Path(dirpath)
        dirnames[:] = [
            name
            for name in sorted(dirnames)
            if name not in config.skip_dirs and not ignore.should_ignore_path(current_dir / name)
        ]

        for name in sorted(filenames):
            file_path = current_dir / name
            if _scan_allowed(file_path, config, ignore):
                discovered.append(file_path)

    return discovered


def is_binary_file(path: Path) -> bool:
    """Heuristically detect binary files by null-byte sampling."""
    try:
        raw = path.read_bytes()[:4096]
    except OSError:
        return True
    return b"\x00" in raw


def _scan_allowed(path: Path, config: LeakLensConfig, ignore: IgnoreMatcher) -> bool:
    if ignore.should_ignore_path(path):
        return False
    if is_binary_file(path):
        return False

    if path.name == ".env":
        return True

    suffix = path.suffix.lower()
    return suffix in config.include_extensions
