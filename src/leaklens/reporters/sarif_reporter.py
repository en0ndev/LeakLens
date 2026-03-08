"""SARIF reporter for code scanning systems."""

from __future__ import annotations

import json

from .. import __version__
from ..models import Finding, ScanResult


def render_sarif(result: ScanResult) -> str:
    """Serialize findings into SARIF 2.1.0 JSON string."""
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LeakLens",
                        "version": __version__,
                        "rules": _build_rules(result.findings),
                    }
                },
                "results": [_finding_to_result(finding) for finding in result.findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def _build_rules(findings: list[Finding]) -> list[dict[str, object]]:
    rules: dict[str, dict[str, object]] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id in rules:
            continue
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.finding_type,
            "shortDescription": {"text": finding.finding_type},
            "fullDescription": {"text": finding.why_risky},
            "help": {
                "text": f"{finding.remediation} {finding.safer_alternative} Autofix: {finding.autofix}",
            },
            "properties": {
                "security-severity": f"{finding.confidence:.2f}",
                "verification-status": finding.verification_status.value,
            },
        }
    return [rules[key] for key in sorted(rules)]


def _finding_to_result(finding: Finding) -> dict[str, object]:
    return {
        "ruleId": _rule_id(finding),
        "level": _sarif_level(finding.severity.value),
        "message": {
            "text": _build_message(finding),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {"startLine": finding.line_number, "snippet": {"text": finding.preview}},
                }
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
        "properties": {"verification-status": finding.verification_status.value},
    }


def _build_message(finding: Finding) -> str:
    base = f"{finding.finding_type} detected. {finding.why_risky} Remediation: {finding.remediation}"
    if finding.verification_status.value == "not_checked":
        return base
    if finding.verification_detail:
        return (
            f"{base} Verification: {finding.verification_status.value} "
            f"({finding.verification_detail})"
        )
    return f"{base} Verification: {finding.verification_status.value}."


def _rule_id(finding: Finding) -> str:
    return (
        finding.finding_type.lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("-", "_")
    )


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
