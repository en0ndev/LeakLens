import subprocess
from pathlib import Path

from leaklens.gitutils import GitClient, parse_unified_diff


def test_parse_unified_diff_extracts_added_lines() -> None:
    diff = """
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,0 +1,2 @@
+token = \"ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD\"
+print(\"ok\")
""".strip()

    lines = parse_unified_diff(diff)
    assert len(lines) == 2
    assert lines[0].file_path == "app.py"
    assert lines[0].line_number == 1


def test_git_client_reads_staged_lines(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, stdout=subprocess.PIPE)

    app_file = tmp_path / "app.py"
    app_file.write_text('token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"\n', encoding="utf-8")

    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True, stdout=subprocess.PIPE)

    client = GitClient(tmp_path)
    lines = client.staged_lines()

    assert lines
    assert any("ghp_" in line.content for line in lines)
