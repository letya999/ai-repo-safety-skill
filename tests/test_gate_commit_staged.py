from __future__ import annotations

import subprocess
from pathlib import Path

from ai_repo_safety.gate import run_gate


def _git(tmp_path: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)


def _init_repo(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "test")
    (tmp_path / "README.md").write_text("ok\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-qm", "init")


def test_commit_gate_ignores_unstaged_secret(tmp_path: Path, monkeypatch) -> None:
    _init_repo(tmp_path)
    (tmp_path / ".env").write_text("SECRET=1\n", encoding="utf-8")

    def fake_which(name: str) -> str | None:
        if name == "gitleaks":
            return "gitleaks"
        return None

    def fake_run(args, cwd=None, timeout=120, env=None):
        if args and args[0] == "gitleaks":
            return 0, "", ""
        from ai_repo_safety.util import run_cmd as real_run

        return real_run(args, cwd=cwd, timeout=timeout, env=env)

    monkeypatch.setattr("ai_repo_safety.gate.which", fake_which)
    monkeypatch.setattr("ai_repo_safety.gate.run_cmd", fake_run)
    assert run_gate(tmp_path, when="commit") == 0


def test_commit_gate_blocks_staged_secret(tmp_path: Path, monkeypatch) -> None:
    _init_repo(tmp_path)
    (tmp_path / ".env").write_text("SECRET=1\n", encoding="utf-8")
    _git(tmp_path, "add", ".env")

    monkeypatch.setattr("ai_repo_safety.gate.which", lambda name: "gitleaks" if name == "gitleaks" else None)
    monkeypatch.setattr(
        "ai_repo_safety.gate.run_cmd",
        lambda args, cwd=None, timeout=120, env=None: (0, "", "") if args and args[0] == "gitleaks" else __import__(
            "ai_repo_safety.util", fromlist=["run_cmd"]
        ).run_cmd(args, cwd=cwd, timeout=timeout, env=env),
    )
    assert run_gate(tmp_path, when="commit") == 1
