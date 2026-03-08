"""Terminal reporter for readable local output."""

from __future__ import annotations

from ..models import Finding, ScanResult


def render_terminal(result: ScanResult) -> str:
    """Render scan result for human-readable terminal display."""
    if not result.findings:
        return (
            "No credential leaks detected.\n"
            f"Files scanned: {result.stats.files_scanned} | "
            f"Files skipped: {result.stats.files_skipped} | "
            f"Lines scanned: {result.stats.lines_scanned}"
        )

    blocks: list[str] = []
    for finding in result.findings:
        blocks.append(_render_finding(finding))

    summary = (
        f"Findings: {len(result.findings)} | "
        f"Files scanned: {result.stats.files_scanned} | "
        f"Files skipped: {result.stats.files_skipped} | "
        f"Lines scanned: {result.stats.lines_scanned}"
    )
    return "\n\n".join(blocks + [summary])


def _render_finding(finding: Finding) -> str:
    sources = ",".join(source.value for source in finding.detector_source)
    return "\n".join(
        [
            f"[{finding.severity.value.upper()}] {finding.finding_type}",
            f"Location: {finding.file_path}:{finding.line_number}",
            f"Confidence: {finding.confidence:.2f} | Detector(s): {sources}",
            f"Preview: {finding.preview}",
            f"Risk: {finding.why_risky}",
            f"Safer Alternative: {finding.safer_alternative}",
            f"Remediation: {finding.remediation}",
            f"Autofix Suggestion: {finding.autofix}",
            f"Fingerprint: {finding.fingerprint}",
        ]
    )
