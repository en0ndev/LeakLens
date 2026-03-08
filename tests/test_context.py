from leaklens.detectors.context import ContextDetector


def test_context_detector_flags_suspicious_assignment() -> None:
    detector = ContextDetector()
    line = 'password = "prod_database_password"'
    matches = detector.scan_line("config.py", 10, line)

    assert any(match.finding_type == "Suspicious Hardcoded Credential" for match in matches)


def test_context_detector_flags_connection_string() -> None:
    detector = ContextDetector()
    line = 'DATABASE_URL="postgres://admin:secret@host/prod"'
    matches = detector.scan_line(".env", 3, line)

    assert any(match.finding_type == "Connection String Credential" for match in matches)


def test_context_detector_ignores_non_secret_paths() -> None:
    detector = ContextDetector()
    line = 'private_key_path = "/etc/ssl/private/server.key"'
    matches = detector.scan_line("settings.py", 4, line)

    assert not any(match.finding_type == "Suspicious Hardcoded Credential" for match in matches)
