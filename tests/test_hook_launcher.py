from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_repo_safety.cli import main


def test_hook_text_uses_python_module_launcher(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    assert main(["install-hooks", "--target", str(tmp_path)]) == 0
    hook = (tmp_path / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert "import ai_repo_safety.gate" in hook
    assert "-m ai_repo_safety" in hook
    assert "exit 1" in hook
    assert "py -3" in hook
    assert "uvx ai-repo-safety" in hook
    assert not (tmp_path / ".git" / "hooks" / "pre-push.cmd").exists()


def test_hook_refuses_when_cli_missing(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    assert main(["install-hooks", "--target", str(tmp_path)]) == 0
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    bash = str(git_bash) if git_bash.exists() else shutil.which("bash")
    if bash and "system32" in bash.lower().replace("\\", "/"):
        # WSL bash cannot execute a Windows temp-path hook file.
        bash = str(git_bash) if git_bash.exists() else None
    if not bash:
        pytest.skip("Git Bash is required to execute the POSIX git hook on Windows")
    env = os.environ.copy()
    env["PATH"] = ""
    proc = subprocess.run(
        [bash, str(hook)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
    )
    assert proc.returncode != 0
    assert "not found" in (proc.stderr + proc.stdout)
