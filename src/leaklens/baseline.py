"""Baseline handling for suppressing previously accepted findings."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


class Baseline:
    """In-memory baseline of finding fingerprints."""

    def __init__(self, fingerprints: set[str] | None = None) -> None:
        self.fingerprints = fingerprints or set()

    @classmethod
    def load(cls, path: Path | None) -> "Baseline":
        """Load baseline file from disk if present."""
        if path is None or not path.exists():
            return cls()

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()

        if isinstance(payload, list):
            return cls({str(item) for item in payload})

        if isinstance(payload, dict):
            fingerprints = payload.get("fingerprints")
            if isinstance(fingerprints, list):
                return cls({str(item) for item in fingerprints})

        return cls()

    def contains(self, finding: Finding) -> bool:
        """Return True when finding fingerprint exists in baseline."""
        return finding.fingerprint in self.fingerprints


def baseline_payload(findings: list[Finding]) -> dict[str, list[str]]:
    """Build serializable baseline payload from findings."""
    return {"fingerprints": sorted({finding.fingerprint for finding in findings})}
