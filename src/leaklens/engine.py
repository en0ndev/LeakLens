"""Scan engine orchestrating detection, filtering, and scoring."""

from __future__ import annotations

import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .baseline import Baseline
from .config import LeakLensConfig
from .detectors import ContextDetector, EntropyDetector, RegexDetector
from .detectors.base import Detector
from .fileio import discover_files
from .gitutils import DiffLine, GitClient
from .ignore import IgnoreMatcher, has_inline_ignore
from .models import (
    SEVERITY_RANK,
    DetectionMatch,
    DetectorSource,
    Finding,
    ScanResult,
    ScanStats,
    Severity,
    build_fingerprint,
    combine_confidence,
    max_severity,
    severity_at_or_above,
)
from .redaction import mask_in_line


class ScanEngine:
    """Primary interface for scanning repositories and git-derived changes."""

    def __init__(self, config: LeakLensConfig, repo_root: Path | None = None) -> None:
        self.config = config
        self.repo_root = (repo_root or Path.cwd()).resolve()
        self.git = GitClient(self.repo_root)
        self.ignore = IgnoreMatcher.from_files(
            root=self.repo_root,
            config_ignored_paths=config.ignored_paths,
            allowlist_values=config.allowlist_values,
            allowlist_patterns=config.allowlist_patterns,
        )
        self.baseline = Baseline.load(_resolve_baseline_path(self.repo_root, config.baseline_file))

        self.regex = RegexDetector(config.all_rules)
        self.entropy = EntropyDetector(config.entropy_threshold)
        self.context = ContextDetector()
        self._detectors: dict[DetectorSource, Detector] = {
            DetectorSource.REGEX: self.regex,
            DetectorSource.ENTROPY: self.entropy,
            DetectorSource.CONTEXT: self.context,
        }

    def scan_repository(self, target: Path) -> ScanResult:
        """Scan complete repository path using parallel file workers."""
        abs_target = (self.repo_root / target).resolve() if not target.is_absolute() else target.resolve()
        files = discover_files(abs_target, self.config, self.ignore)

        stats = ScanStats()
        findings: list[Finding] = []

        with ThreadPoolExecutor(max_workers=max(1, self.config.max_workers)) as executor:
            futures = {executor.submit(self._scan_file, file_path): file_path for file_path in files}
            for future in as_completed(futures):
                file_findings, file_stats = future.result()
                findings.extend(file_findings)
                stats.files_scanned += file_stats.files_scanned
                stats.files_skipped += file_stats.files_skipped
                stats.lines_scanned += file_stats.lines_scanned

        return self._finalize(findings, stats)

    def scan_staged(self) -> ScanResult:
        """Scan staged diff lines from git index."""
        return self._scan_diff_lines(self.git.staged_lines())

    def scan_commit(self, commit_hash: str) -> ScanResult:
        """Scan one commit's added lines."""
        return self._scan_diff_lines(self.git.commit_lines(commit_hash))

    def scan_diff(self, base: str, head: str) -> ScanResult:
        """Scan a diff range's added lines."""
        return self._scan_diff_lines(self.git.diff_lines(base, head))

    def _scan_diff_lines(self, lines: list[DiffLine]) -> ScanResult:
        stats = ScanStats()
        findings: list[Finding] = []
        scanned_files: set[str] = set()

        for line in lines:
            file_path = self.repo_root / line.file_path
            if self.ignore.should_ignore_path(file_path):
                continue
            if _path_has_skipped_dir(file_path, self.repo_root, self.config.skip_dirs):
                continue
            if not _is_supported_by_extension(file_path, self.config):
                continue
            if has_inline_ignore(line.content, self.config.inline_ignore_marker):
                continue

            scanned_files.add(line.file_path)
            stats.lines_scanned += 1
            findings.extend(self._scan_line(line.file_path, line.line_number, line.content))

        stats.files_scanned = len(scanned_files)
        return self._finalize(findings, stats)

    def _scan_file(self, file_path: Path) -> tuple[list[Finding], ScanStats]:
        stats = ScanStats(files_scanned=1)
        findings: list[Finding] = []
        ignore_next = False

        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return [], ScanStats(files_scanned=0, files_skipped=1, lines_scanned=0)

        try:
            relative = file_path.resolve().relative_to(self.repo_root.resolve()).as_posix()
        except ValueError:
            relative = file_path.resolve().as_posix()

        for index, line in enumerate(lines, start=1):
            if has_inline_ignore(line, self.config.inline_ignore_marker):
                if _is_comment_line(line):
                    ignore_next = True
                continue

            if ignore_next:
                ignore_next = False
                continue

            stats.lines_scanned += 1
            findings.extend(self._scan_line(relative, index, line))

        return findings, stats

    def _scan_line(self, file_path: str, line_number: int, line: str) -> list[Finding]:
        raw_matches: list[DetectionMatch] = []

        for source in sorted(self.config.enabled_detectors, key=lambda item: item.value):
            detector = self._detectors[source]
            raw_matches.extend(detector.scan_line(file_path, line_number, line))

        if not raw_matches:
            return []

        raw_matches = _suppress_overlapping_entropy(raw_matches)

        grouped: dict[tuple[str, int, int], list[DetectionMatch]] = defaultdict(list)
        for match in raw_matches:
            grouped[(match.value, match.start, match.end)].append(match)

        findings: list[Finding] = []
        for (value, _, _), matches in grouped.items():
            if self.ignore.is_allowlisted(value):
                continue

            top_match = max(matches, key=lambda item: item.confidence)
            confidence = combine_confidence([item.confidence for item in matches])
            severity = max_severity([item.severity for item in matches])
            sources = sorted({item.source for item in matches}, key=lambda item: item.value)
            risks = _join_unique([item.risk for item in matches])
            remediations = _join_unique([item.remediation for item in matches])
            autofixes = _join_unique([item.autofix for item in matches])

            finding = Finding(
                finding_type=top_match.finding_type,
                file_path=file_path,
                line_number=line_number,
                preview=mask_in_line(line, value),
                detector_source=sources,
                confidence=confidence,
                severity=severity,
                why_risky=risks,
                safer_alternative=top_match.safer_alternative,
                remediation=remediations,
                autofix=autofixes,
                fingerprint=build_fingerprint(file_path, line_number, top_match.finding_type, value),
                raw_value=value,
            )

            if self.baseline.contains(finding):
                continue

            findings.append(finding)

        return findings

    def _finalize(self, findings: list[Finding], stats: ScanStats) -> ScanResult:
        ordered = sorted(
            findings,
            key=lambda item: (
                item.file_path,
                item.line_number,
                -SEVERITY_RANK[item.severity],
                item.finding_type,
                item.preview,
            ),
        )
        return ScanResult(findings=ordered, stats=stats)


def should_fail(findings: list[Finding], threshold: Severity) -> bool:
    """Return True when findings include severity at or above threshold."""
    return any(severity_at_or_above(finding.severity, threshold) for finding in findings)


def _resolve_baseline_path(repo_root: Path, baseline_file: str | None) -> Path | None:
    if baseline_file is None:
        return None
    candidate = Path(baseline_file)
    if candidate.is_absolute():
        return candidate
    return repo_root / candidate


def _is_supported_by_extension(path: Path, config: LeakLensConfig) -> bool:
    if _is_dotenv_style(path):
        return True
    return path.suffix.lower() in config.include_extensions


def _is_dotenv_style(path: Path) -> bool:
    """Return True for dotenv files like .env and .env.example."""
    return path.name == ".env" or path.name.startswith(".env.")


def _is_comment_line(line: str) -> bool:
    return bool(re.match(r"^\s*(#|//|;|/\*|\*)", line))


def _join_unique(values: list[str]) -> str:
    unique = []
    seen: set[str] = set()
    for value in values:
        normalized = value.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
    return " ".join(unique)


def _path_has_skipped_dir(path: Path, root: Path, skip_dirs: set[str]) -> bool:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        relative = path
    return any(part in skip_dirs for part in relative.parts)


def _suppress_overlapping_entropy(matches: list[DetectionMatch]) -> list[DetectionMatch]:
    regex_context_ranges: list[tuple[int, int]] = [
        (match.start, match.end)
        for match in matches
        if match.source in {DetectorSource.REGEX, DetectorSource.CONTEXT}
    ]
    if not regex_context_ranges:
        return matches

    filtered: list[DetectionMatch] = []
    for match in matches:
        if match.source != DetectorSource.ENTROPY:
            filtered.append(match)
            continue
        if any(_ranges_overlap(match.start, match.end, start, end) for start, end in regex_context_ranges):
            continue
        filtered.append(match)

    return filtered


def _ranges_overlap(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and start_b < end_a
