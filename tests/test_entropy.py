from leaklens.detectors.entropy import EntropyDetector, shannon_entropy


def test_shannon_entropy_values() -> None:
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0
    assert shannon_entropy("AbCd1234+/ZX90qweRTY") > 3.5


def test_entropy_detector_flags_high_entropy_candidates() -> None:
    detector = EntropyDetector(threshold=3.8)
    line = 'token = "A9xD2qLk0+/Yt7PwR3VmNs8H"'
    matches = detector.scan_line("app.py", 1, line)

    assert matches
    assert matches[0].finding_type == "High Entropy Secret"


def test_entropy_detector_ignores_assignment_prefix_noise() -> None:
    detector = EntropyDetector(threshold=3.8)
    line = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"
    matches = detector.scan_line(".env", 1, line)

    values = [match.value for match in matches]
    assert "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD" not in values
