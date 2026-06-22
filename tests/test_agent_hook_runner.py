from __future__ import annotations

import os
import subprocess  # nosec
import sys
from pathlib import Path

from ai_repo_safety.cli import main


def test_agent_hook_runner_skips_non_sensitive_command(tmp_path: Path) -> None:
    main(["install-agent-hooks", "--target", str(tmp_path), "--tool", "codex"])
    script = tmp_path / "scripts" / "security" / "agent_hook_runner.py"
    proc = subprocess.run(  # nosec
        [sys.executable, str(script), "--profile", "sensitive-preflight", "--command", "python -m pytest"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert proc.stderr == ""


def test_agent_hook_runner_blocks_sensitive_command_when_scanner_missing(tmp_path: Path) -> None:
    main(["install-agent-hooks", "--target", str(tmp_path), "--tool", "codex"])
    script = tmp_path / "scripts" / "security" / "agent_hook_runner.py"
    env = os.environ.copy()
    env["PATH"] = ""
    proc = subprocess.run(  # nosec
        [sys.executable, str(script), "--profile", "sensitive-preflight", "--command", "git push origin dev"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert proc.returncode == 2
    assert "required scanner `gitleaks` is missing" in proc.stderr


def test_install_agent_hooks_refuses_existing_config_without_overwrite(tmp_path: Path) -> None:
    codex_dir = tmp_path / ".codex"
    codex_dir.mkdir(parents=True)
    (codex_dir / "hooks.json").write_text('{"hooks":{}}', encoding="utf-8")
    code = main(["install-agent-hooks", "--target", str(tmp_path), "--tool", "codex"])
    assert code == 4
