"""Configuration loading and normalization for LeakLens."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import DetectorSource, RuleSpec, Severity
from .rules import builtin_rules

DEFAULT_EXTENSIONS = {
    ".env",
    ".go",
    ".java",
    ".js",
    ".json",
    ".py",
    ".sh",
    ".tf",
    ".toml",
    ".ts",
    ".yaml",
    ".yml",
}

DEFAULT_SKIP_DIRS = {".git", ".venv", "build", "coverage", "dist", "node_modules"}


@dataclass
class LeakLensConfig:
    """Runtime settings controlling scanner behavior."""

    entropy_threshold: float = 4.2
    severity_threshold: Severity = Severity.MEDIUM
    enabled_detectors: set[DetectorSource] = field(
        default_factory=lambda: {DetectorSource.REGEX, DetectorSource.ENTROPY, DetectorSource.CONTEXT}
    )
    ignored_paths: list[str] = field(default_factory=list)
    allowlist_values: set[str] = field(default_factory=set)
    allowlist_patterns: list[str] = field(default_factory=list)
    baseline_file: str | None = None
    default_output_format: str = "terminal"
    max_workers: int = 8
    include_extensions: set[str] = field(default_factory=lambda: set(DEFAULT_EXTENSIONS))
    skip_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_SKIP_DIRS))
    custom_rules: list[RuleSpec] = field(default_factory=list)
    inline_ignore_marker: str = "leaklens:ignore"

    @property
    def all_rules(self) -> list[RuleSpec]:
        """Return built-in rules plus custom rules."""
        return builtin_rules() + self.custom_rules


def load_config(path: Path | None) -> LeakLensConfig:
    """Load configuration from YAML file, returning sane defaults on failure."""
    config = LeakLensConfig()
    if path is None or not path.exists():
        return config

    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return config

    if not isinstance(payload, dict):
        return config

    config.entropy_threshold = _as_float(payload.get("entropy_threshold"), config.entropy_threshold)
    config.severity_threshold = _parse_severity(payload.get("severity_threshold"), config.severity_threshold)
    config.enabled_detectors = _parse_detectors(payload.get("enabled_detectors"), config.enabled_detectors)
    config.ignored_paths = _as_string_list(payload.get("ignored_paths"))

    allowlist = payload.get("allowlist", {})
    if isinstance(allowlist, dict):
        config.allowlist_values = set(_as_string_list(allowlist.get("values")))
        config.allowlist_patterns = _as_string_list(allowlist.get("patterns"))

    output = payload.get("output", {})
    if isinstance(output, dict):
        default_format = output.get("default_format")
        if isinstance(default_format, str) and default_format in {"terminal", "json", "sarif"}:
            config.default_output_format = default_format

    scan = payload.get("scan", {})
    if isinstance(scan, dict):
        config.max_workers = max(1, _as_int(scan.get("max_workers"), config.max_workers))

    baseline = payload.get("baseline_file")
    if isinstance(baseline, str) and baseline.strip():
        config.baseline_file = baseline.strip()

    extensions = payload.get("include_extensions")
    if isinstance(extensions, list):
        config.include_extensions = {str(ext) for ext in extensions if isinstance(ext, str)}

    skip_dirs = payload.get("skip_dirs")
    if isinstance(skip_dirs, list):
        config.skip_dirs = {str(item) for item in skip_dirs if isinstance(item, str)}

    custom_rules = payload.get("rules")
    if isinstance(custom_rules, list):
        config.custom_rules = _parse_custom_rules(custom_rules)

    marker = payload.get("inline_ignore_marker")
    if isinstance(marker, str) and marker.strip():
        config.inline_ignore_marker = marker.strip()

    return config


def discover_config_path(explicit_path: Path | None = None) -> Path | None:
    """Resolve config path from explicit argument or local default file."""
    if explicit_path is not None:
        return explicit_path
    default = Path("leaklens.yml")
    return default if default.exists() else None


def _parse_custom_rules(entries: list[object]) -> list[RuleSpec]:
    parsed: list[RuleSpec] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        regex = entry.get("regex")
        if not isinstance(name, str) or not isinstance(regex, str):
            continue

        secret_type = entry.get("secret_type")
        severity = _parse_severity(entry.get("severity"), Severity.MEDIUM)
        confidence = max(0.2, min(0.99, _as_float(entry.get("confidence"), 0.85)))
        remediation = entry.get("remediation")

        parsed.append(
            RuleSpec(
                name=name,
                secret_type=secret_type if isinstance(secret_type, str) and secret_type else name,
                pattern=regex,
                severity=severity,
                confidence=confidence,
                risk=f"Custom detection rule '{name}' identified a potentially sensitive value.",
                remediation=(
                    remediation
                    if isinstance(remediation, str) and remediation.strip()
                    else "Move sensitive values to secure secret storage and rotate if exposed."
                ),
            )
        )

    return parsed


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    return []


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_detectors(value: Any, default: set[DetectorSource]) -> set[DetectorSource]:
    if not isinstance(value, list):
        return set(default)

    parsed: set[DetectorSource] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        normalized = item.strip().lower()
        if normalized == DetectorSource.REGEX.value:
            parsed.add(DetectorSource.REGEX)
        elif normalized == DetectorSource.ENTROPY.value:
            parsed.add(DetectorSource.ENTROPY)
        elif normalized == DetectorSource.CONTEXT.value:
            parsed.add(DetectorSource.CONTEXT)

    return parsed or set(default)


def _parse_severity(value: Any, default: Severity) -> Severity:
    if isinstance(value, str):
        lowered = value.strip().lower()
        for severity in Severity:
            if severity.value == lowered:
                return severity
    return default
