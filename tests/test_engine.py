import subprocess
from pathlib import Path

from leaklens.config import LeakLensConfig
from leaklens.engine import ScanEngine


def test_engine_suppresses_entropy_when_regex_hits_same_value(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD\n",
        encoding="utf-8",
    )

    engine = ScanEngine(LeakLensConfig(), repo_root=tmp_path)
    result = engine.scan_repository(tmp_path)

    assert result.findings
    assert len(result.findings) == 1
    assert result.findings[0].finding_type == "GitHub Token"


def test_staged_scan_skips_dist_directory(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, stdout=subprocess.PIPE)

    dist_dir = tmp_path / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    secret_file = dist_dir / "bundle.js"
    secret_file.write_text(
        'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";\n',
        encoding="utf-8",
    )

    subprocess.run(["git", "add", "dist/bundle.js"], cwd=tmp_path, check=True, stdout=subprocess.PIPE)

    engine = ScanEngine(LeakLensConfig(), repo_root=tmp_path)
    result = engine.scan_staged()

    assert result.findings == []
