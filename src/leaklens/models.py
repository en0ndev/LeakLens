"""Core domain models used by LeakLens."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Any


class Severity(str, Enum):
    """Severity levels ordered by operational risk."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class DetectorSource(str, Enum):
    """Detectors that can produce a finding."""

    REGEX = "regex"
    ENTROPY = "entropy"
    CONTEXT = "context"


@dataclass(frozen=True)
class RuleSpec:
    """A secret detection rule specification."""

    name: str
    secret_type: str
    pattern: str
    severity: Severity
    confidence: float
    risk: str
    remediation: str
    value_group: int = 0


@dataclass(frozen=True)
class DetectionMatch:
    """A match emitted by a detector for one line."""

    finding_type: str
    value: str
    start: int
    end: int
    source: DetectorSource
    confidence: float
    severity: Severity
    risk: str
    remediation: str
    safer_alternative: str
    autofix: str


@dataclass
class Finding:
    """Final merged finding returned to reporters and CI."""

    finding_type: str
    file_path: str
    line_number: int
    preview: str
    detector_source: list[DetectorSource]
    confidence: float
    severity: Severity
    why_risky: str
    safer_alternative: str
    remediation: str
    autofix: str
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to a deterministic dictionary."""
        return {
            "finding_type": self.finding_type,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "preview": self.preview,
            "detector_source": [item.value for item in self.detector_source],
            "confidence": round(self.confidence, 4),
            "severity": self.severity.value,
            "why_risky": self.why_risky,
            "safer_alternative": self.safer_alternative,
            "remediation": self.remediation,
            "autofix": self.autofix,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanStats:
    """Aggregate scan metrics."""

    files_scanned: int = 0
    files_skipped: int = 0
    lines_scanned: int = 0


@dataclass
class ScanResult:
    """Complete scan output."""

    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)


def build_fingerprint(file_path: str, line_number: int, finding_type: str, value: str) -> str:
    """Build a stable fingerprint for baseline suppression."""
    payload = f"{file_path}:{line_number}:{finding_type}:{sha256(value.encode('utf-8')).hexdigest()}"
    return sha256(payload.encode("utf-8")).hexdigest()


def combine_confidence(scores: list[float]) -> float:
    """Combine detector confidences into one score."""
    if not scores:
        return 0.0
    aggregate = 1.0
    for score in scores:
        bounded = max(0.01, min(0.99, score))
        aggregate *= 1 - bounded
    return round(max(0.0, min(0.99, 1 - aggregate)), 4)


def max_severity(severities: list[Severity]) -> Severity:
    """Return the highest severity in the given collection."""
    if not severities:
        return Severity.LOW
    return max(severities, key=lambda sev: SEVERITY_RANK[sev])


def severity_at_or_above(actual: Severity, threshold: Severity) -> bool:
    """Check whether severity meets or exceeds threshold."""
    return SEVERITY_RANK[actual] >= SEVERITY_RANK[threshold]
