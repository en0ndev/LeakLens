"""Git integration for staged, commit, and range scans."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DiffLine:
    """Represents one added line from a unified diff."""

    file_path: str
    line_number: int
    content: str


_HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitClient:
    """Wrapper over git commands used by scan modes."""

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    def is_repository(self) -> bool:
        """Return True when cwd is inside a Git worktree."""
        return self._run(["rev-parse", "--is-inside-work-tree"])[0] == 0

    def staged_lines(self) -> list[DiffLine]:
        """Return added lines from staged changes."""
        code, out = self._run(["diff", "--cached", "--unified=0", "--no-color"])
        return parse_unified_diff(out) if code == 0 else []

    def commit_lines(self, commit_hash: str) -> list[DiffLine]:
        """Return added lines from a specific commit."""
        code, out = self._run(["show", "--unified=0", "--no-color", "--format=", commit_hash])
        return parse_unified_diff(out) if code == 0 else []

    def diff_lines(self, base: str, head: str) -> list[DiffLine]:
        """Return added lines from base..head diff."""
        code, out = self._run(["diff", "--unified=0", "--no-color", f"{base}..{head}"])
        return parse_unified_diff(out) if code == 0 else []

    def _run(self, args: list[str]) -> tuple[int, str]:
        proc = subprocess.run(
            ["git", *args],
            cwd=self.repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout


def parse_unified_diff(text: str) -> list[DiffLine]:
    """Parse unified diff text into added lines with destination line numbers."""
    lines: list[DiffLine] = []
    current_file: str | None = None
    destination_line = 0

    for raw in text.splitlines():
        if raw.startswith("+++"):
            token = raw[4:].strip()
            if token == "/dev/null":
                current_file = None
            elif token.startswith("b/"):
                current_file = token[2:]
            else:
                current_file = token
            continue

        hunk = _HUNK_PATTERN.match(raw)
        if hunk:
            destination_line = int(hunk.group(1))
            continue

        if current_file is None:
            continue

        if raw.startswith("+") and not raw.startswith("+++"):
            lines.append(DiffLine(current_file, destination_line, raw[1:]))
            destination_line += 1
            continue

        if raw.startswith("-") and not raw.startswith("---"):
            continue

        if raw.startswith("\\"):
            continue

        destination_line += 1

    return lines
