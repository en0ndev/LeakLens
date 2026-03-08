import json

from leaklens.models import DetectorSource, Finding, ScanResult, ScanStats, Severity
from leaklens.reporters.sarif_reporter import render_sarif


def test_sarif_report_contains_required_fields() -> None:
    finding = Finding(
        finding_type="GitHub Token",
        file_path="app.py",
        line_number=12,
        preview='token = "ghp_****ABCD"',
        detector_source=[DetectorSource.REGEX],
        confidence=0.95,
        severity=Severity.HIGH,
        why_risky="GitHub token can access repositories.",
        safer_alternative="Use a secret manager.",
        remediation="Rotate and replace with env var.",
        autofix="Replace literal with os.getenv('GITHUB_TOKEN').",
        fingerprint="abc123",
    )
    result = ScanResult(findings=[finding], stats=ScanStats(files_scanned=1, lines_scanned=1))

    payload = json.loads(render_sarif(result))

    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"][0]["ruleId"] == "github_token"
    assert payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"][
        "startLine"
    ] == 12
