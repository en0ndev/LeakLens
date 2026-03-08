from leaklens.detectors.regex import RegexDetector
from leaklens.rules import builtin_rules


def test_regex_detector_finds_github_token() -> None:
    detector = RegexDetector(builtin_rules())
    line = 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"'
    matches = detector.scan_line("app.py", 1, line)

    assert any(match.finding_type == "GitHub Token" for match in matches)


def test_regex_detector_finds_db_url_with_credentials() -> None:
    detector = RegexDetector(builtin_rules())
    line = 'db_url = "postgres://admin:secretpass@db.local/prod"'
    matches = detector.scan_line("settings.py", 2, line)

    assert any(match.finding_type == "Database URL Credentials" for match in matches)


def test_regex_detector_skips_placeholder_env_values() -> None:
    detector = RegexDetector(builtin_rules())
    line = "API_KEY=example"
    matches = detector.scan_line(".env", 3, line)

    assert not any(match.finding_type == ".env Secret" for match in matches)


def test_regex_detector_ignores_private_key_marker_in_pattern_literal() -> None:
    detector = RegexDetector(builtin_rules())
    line = 'pattern = r"-----BEGIN RSA PRIVATE KEY-----"'
    matches = detector.scan_line("rules.py", 4, line)

    assert not any(match.finding_type == "RSA Private Key" for match in matches)


def test_regex_detector_requires_jwt_context_keyword() -> None:
    detector = RegexDetector(builtin_rules())
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG5Eb2UiLCJpYXQiOjE1MTYyMzkwMjJ9."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    line = f'value = "{jwt}"'
    matches = detector.scan_line("app.py", 5, line)

    assert not any(match.finding_type == "JWT Token" for match in matches)
