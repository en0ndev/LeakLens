from pathlib import Path

from typer.testing import CliRunner

from leaklens.cli import app


def test_cli_scan_json_and_nonzero_exit(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"\n', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--fail-on", "low"])

    assert result.exit_code == 1
    assert '"findings"' in result.stdout


def test_cli_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "leaklens" in result.stdout
