from __future__ import annotations

from pathlib import Path

from ai_repo_safety.cli import main


def test_doctor_runs() -> None:
    code = main(["doctor"])
    assert code in (0, 2)


def test_init_project(tmp_path: Path) -> None:
    code = main(["init", "--target", str(tmp_path), "--python", "yes", "--github", "no"])
    assert code == 0
    assert (tmp_path / ".gitignore").exists()
    assert (tmp_path / ".dockerignore").exists()
    assert (tmp_path / ".env.example").exists()
    assert (tmp_path / "AGENTS.md").exists()
    assert (tmp_path / "scripts" / "security" / "forbid_sensitive_files.py").exists()


def test_setup_project(tmp_path: Path) -> None:
    import subprocess
    subprocess.run(["git", "init"], cwd=tmp_path, check=True)
    code = main(["setup", "--target", str(tmp_path), "--python", "yes", "--github", "no"])
    assert code == 0
    assert (tmp_path / ".gitignore").exists()
    assert (tmp_path / ".dockerignore").exists()
    assert (tmp_path / ".env.example").exists()
    assert (tmp_path / "AGENTS.md").exists()
    assert (tmp_path / "scripts" / "security" / "forbid_sensitive_files.py").exists()

