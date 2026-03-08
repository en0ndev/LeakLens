"""JSON reporter for CI and machine integrations."""

from __future__ import annotations

import json

from .. import __version__
from ..models import ScanResult


def render_json(result: ScanResult) -> str:
    """Serialize scan result into deterministic JSON."""
    payload = {
        "tool": "LeakLens",
        "version": __version__,
        "summary": {
            "findings": len(result.findings),
            "files_scanned": result.stats.files_scanned,
            "files_skipped": result.stats.files_skipped,
            "lines_scanned": result.stats.lines_scanned,
        },
        "findings": [finding.to_dict() for finding in result.findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
