from __future__ import annotations

import subprocess  # nosec
from pathlib import Path

from ai_repo_safety.git_integrity import collect_integrity_warnings


def _git(tmp_path: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True, text=True)  # nosec


def _init_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Test User")
    _git(tmp_path, "config", "user.email", "test@example.com")


def test_collect_integrity_warnings_flags_missing_upstream_and_unsigned_head(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "README.md").write_text("hello\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-m", "init")

    warnings = collect_integrity_warnings(tmp_path)
    assert any("has no upstream configured" in item for item in warnings)
    assert any("not locally verifiable as signed" in item.lower() or "no signature" in item.lower() for item in warnings)


def test_collect_integrity_warnings_flags_recent_amend_in_reflog(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    target = tmp_path / "README.md"
    target.write_text("hello\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-m", "init")
    target.write_text("hello world\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "--amend", "-m", "init amended")

    warnings = collect_integrity_warnings(tmp_path)
    assert any("reflog includes history-rewrite style operations" in item for item in warnings)
