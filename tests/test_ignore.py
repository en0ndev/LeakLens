from pathlib import Path
import subprocess

from leaklens.config import LeakLensConfig
from leaklens.engine import ScanEngine
from leaklens.ignore import IgnoreMatcher, has_inline_ignore


def test_ignore_matcher_uses_ignore_file(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".leaklensignore"
    ignore_file.write_text("secrets/**\n", encoding="utf-8")

    matcher = IgnoreMatcher.from_files(tmp_path, [], set(), [])
    assert matcher.should_ignore_path(tmp_path / "secrets" / "config.py")


def test_ignore_matcher_supports_legacy_ignore_file(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".aicredleakignore"
    ignore_file.write_text("legacy/**\n", encoding="utf-8")

    matcher = IgnoreMatcher.from_files(tmp_path, [], set(), [])
    assert matcher.should_ignore_path(tmp_path / "legacy" / "config.py")


def test_inline_ignore_skips_next_line(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        """
# leaklens:ignore
password = "prod_database_password"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    engine = ScanEngine(LeakLensConfig(), repo_root=tmp_path)
    result = engine.scan_repository(tmp_path)

    assert result.findings == []
    assert has_inline_ignore("# leaklens:ignore", "leaklens:ignore")


def test_ignore_matcher_respects_gitignore(tmp_path: Path) -> None:
    try:
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True, text=True)
    except OSError:
        return

    (tmp_path / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    (tmp_path / "ignored.py").write_text('token = "ghp_abcdefghijklmnopqrstuvwxy123456ABCD"\n', encoding="utf-8")
    (tmp_path / "tracked.py").write_text("print('ok')\n", encoding="utf-8")

    matcher = IgnoreMatcher.from_files(tmp_path, [], set(), [])
    assert matcher.should_ignore_path(tmp_path / "ignored.py")
    assert not matcher.should_ignore_path(tmp_path / "tracked.py")
