from __future__ import annotations

import subprocess
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
    """Plan-only setup: the default must not touch the host system, install
    global tools, or call any GitHub API. CI must be able to run this
    test on a machine with no network, no gh auth, and missing optional
    scanners."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True)
    code = main(["setup", "--target", str(tmp_path), "--python", "yes", "--github", "no"])
    assert code == 0, "plan-only setup must always succeed on a clean checkout"
    assert (tmp_path / ".gitignore").exists()
    assert (tmp_path / ".dockerignore").exists()
    assert (tmp_path / ".env.example").exists()
    assert (tmp_path / "AGENTS.md").exists()
    assert (tmp_path / "scripts" / "security" / "forbid_sensitive_files.py").exists()
    # Plan mode must not have installed git hooks.
    assert not (tmp_path / ".git" / "hooks" / "pre-push").exists(), (
        "plan-only setup must not install git hooks"
    )


def test_setup_apply_refuses_without_yes(tmp_path: Path) -> None:
    """Apply mode is gated on --yes so scripted invocations cannot
    silently inherit a YOLO posture."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True)
    code = main([
        "setup",
        "--target", str(tmp_path),
        "--python", "yes",
        "--github", "no",
        "--apply",
        "--install-tools",
    ])
    assert code == 2, "apply mode without --yes must refuse with exit 2"

