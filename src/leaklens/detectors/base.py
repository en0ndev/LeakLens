"""Base detector protocol."""

from __future__ import annotations

from typing import Protocol

from ..models import DetectionMatch


class Detector(Protocol):
    """Detector interface used by scan engine."""

    def scan_line(self, file_path: str, line_number: int, line: str) -> list[DetectionMatch]:
        """Return all matches for one line."""
        ...
