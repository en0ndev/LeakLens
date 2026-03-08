"""Optional finding verification checks."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Callable
from urllib import error, parse, request

from .models import Finding, VerificationStatus

PLACEHOLDER_MARKERS = {
    "example",
    "placeholder",
    "dummy",
    "changeme",
    "replace_me",
    "your_token_here",
    "your-key",
    "fake",
    "redacted",
}


def verify_findings(findings: list[Finding], timeout_seconds: float = 4.0) -> None:
    """Verify supported finding types in place."""
    for finding in findings:
        value = finding.raw_value.strip()
        if not value:
            _set_status(finding, VerificationStatus.UNVERIFIABLE, "Raw secret value unavailable for verification.")
            continue
        if _is_placeholder(value):
            _set_status(finding, VerificationStatus.PLACEHOLDER, "Value appears to be a placeholder/template.")
            continue

        status, detail = _verify_one(finding, value, timeout_seconds)
        _set_status(finding, status, detail)


def _verify_one(finding: Finding, value: str, timeout_seconds: float) -> tuple[VerificationStatus, str]:
    if finding.finding_type == "GitHub Token":
        return _verify_github(value, timeout_seconds)
    if finding.finding_type == "Stripe Secret Key":
        return _verify_stripe(value, timeout_seconds)
    if finding.finding_type == "Slack Token":
        return _verify_slack(value, timeout_seconds)
    if finding.finding_type == "JWT Token":
        return _verify_jwt(value)
    if finding.finding_type in {"SSH Private Key", "RSA Private Key"}:
        return (
            VerificationStatus.UNVERIFIABLE,
            "Private key verification is not performed online; inspect key provenance and rotate if exposed.",
        )
    if finding.finding_type in {"AWS Access Key", "AWS Secret Key"}:
        return (
            VerificationStatus.UNVERIFIABLE,
            "AWS validity checks require signed AWS API requests with credentials and are not attempted here.",
        )
    return (
        VerificationStatus.LIKELY_SECRET,
        "No provider-specific verifier configured for this secret type.",
    )


def _verify_github(token: str, timeout_seconds: float) -> tuple[VerificationStatus, str]:
    code, _ = _http_request(
        "https://api.github.com/user",
        timeout_seconds=timeout_seconds,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "leaklens",
        },
    )
    if code == 200:
        return VerificationStatus.VERIFIED_ACTIVE, "GitHub API accepted the token."
    if code in {401, 403}:
        return VerificationStatus.VERIFIED_INVALID, "GitHub API rejected the token."
    if code == 0:
        return VerificationStatus.VERIFICATION_ERROR, "Network error while contacting GitHub API."
    return VerificationStatus.UNVERIFIABLE, f"GitHub API returned unexpected status code {code}."


def _verify_stripe(key: str, timeout_seconds: float) -> tuple[VerificationStatus, str]:
    auth = base64.b64encode(f"{key}:".encode("utf-8")).decode("ascii")
    code, _ = _http_request(
        "https://api.stripe.com/v1/account",
        timeout_seconds=timeout_seconds,
        headers={"Authorization": f"Basic {auth}", "User-Agent": "leaklens"},
    )
    if code == 200:
        return VerificationStatus.VERIFIED_ACTIVE, "Stripe API accepted the key."
    if code in {401, 403}:
        return VerificationStatus.VERIFIED_INVALID, "Stripe API rejected the key."
    if code == 0:
        return VerificationStatus.VERIFICATION_ERROR, "Network error while contacting Stripe API."
    return VerificationStatus.UNVERIFIABLE, f"Stripe API returned unexpected status code {code}."


def _verify_slack(token: str, timeout_seconds: float) -> tuple[VerificationStatus, str]:
    body = parse.urlencode({}).encode("utf-8")
    code, payload = _http_request(
        "https://slack.com/api/auth.test",
        timeout_seconds=timeout_seconds,
        method="POST",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "leaklens",
        },
    )

    if code == 200:
        try:
            data = json.loads(payload) if payload else {}
        except json.JSONDecodeError:
            return VerificationStatus.UNVERIFIABLE, "Slack API returned non-JSON verification response."
        if bool(data.get("ok")):
            return VerificationStatus.VERIFIED_ACTIVE, "Slack API accepted the token."
        return VerificationStatus.VERIFIED_INVALID, "Slack API rejected the token."
    if code in {401, 403}:
        return VerificationStatus.VERIFIED_INVALID, "Slack API rejected the token."
    if code == 0:
        return VerificationStatus.VERIFICATION_ERROR, "Network error while contacting Slack API."
    return VerificationStatus.UNVERIFIABLE, f"Slack API returned unexpected status code {code}."


def _verify_jwt(token: str) -> tuple[VerificationStatus, str]:
    parts = token.split(".")
    if len(parts) != 3:
        return VerificationStatus.VERIFIED_INVALID, "JWT does not have 3 segments."
    header_raw = _decode_b64url(parts[0])
    payload_raw = _decode_b64url(parts[1])
    if header_raw is None or payload_raw is None:
        return VerificationStatus.VERIFIED_INVALID, "JWT segments are not valid base64url."

    try:
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except json.JSONDecodeError:
        return VerificationStatus.VERIFIED_INVALID, "JWT header or payload is not valid JSON."

    if not isinstance(header, dict) or not isinstance(payload, dict):
        return VerificationStatus.VERIFIED_INVALID, "JWT header/payload must be JSON objects."

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        now = datetime.now(tz=UTC).timestamp()
        if exp < now:
            return VerificationStatus.VERIFIED_INVALID, "JWT is syntactically valid but expired."
    return VerificationStatus.UNVERIFIABLE, "JWT is syntactically valid; signature/issuer not verified."


def _http_request(
    url: str,
    *,
    timeout_seconds: float,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    opener: Callable[..., object] = request.urlopen,
) -> tuple[int, str]:
    req = request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with opener(req, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8", errors="replace")
            return int(response.getcode()), body
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return int(exc.code), body
    except (error.URLError, TimeoutError, OSError):
        return 0, ""


def _decode_b64url(value: str) -> str | None:
    padding = "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _set_status(finding: Finding, status: VerificationStatus, detail: str) -> None:
    finding.verification_status = status
    finding.verification_detail = detail.strip()
