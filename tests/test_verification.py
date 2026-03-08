from unittest.mock import patch

from leaklens.models import DetectorSource, Finding, Severity, VerificationStatus
from leaklens.verification import verify_findings


def _make_finding(finding_type: str, raw_value: str) -> Finding:
    return Finding(
        finding_type=finding_type,
        file_path="app.py",
        line_number=1,
        preview="token=****",
        detector_source=[DetectorSource.REGEX],
        confidence=0.9,
        severity=Severity.HIGH,
        why_risky="risk",
        safer_alternative="safe",
        remediation="remediate",
        autofix="autofix",
        fingerprint="fp",
        raw_value=raw_value,
    )


def test_verify_marks_placeholder_values() -> None:
    finding = _make_finding("GitHub Token", "ghp_example_placeholder_token")
    verify_findings([finding])

    assert finding.verification_status == VerificationStatus.PLACEHOLDER


def test_verify_marks_active_github_token_from_http_200() -> None:
    finding = _make_finding("GitHub Token", "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD")
    with patch("leaklens.verification._http_request", return_value=(200, "{}")):
        verify_findings([finding])

    assert finding.verification_status == VerificationStatus.VERIFIED_ACTIVE


def test_verify_marks_invalid_github_token_from_http_401() -> None:
    finding = _make_finding("GitHub Token", "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD")
    with patch("leaklens.verification._http_request", return_value=(401, "{}")):
        verify_findings([finding])

    assert finding.verification_status == VerificationStatus.VERIFIED_INVALID


def test_verify_jwt_marks_expired_tokens_invalid() -> None:
    finding = _make_finding(
        "JWT Token",
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJleHAiOjE1MTYyMzkwMjJ9."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ),
    )
    verify_findings([finding])

    assert finding.verification_status == VerificationStatus.VERIFIED_INVALID
