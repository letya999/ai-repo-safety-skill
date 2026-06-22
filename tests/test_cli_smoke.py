from __future__ import annotations

import json
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
    assert (tmp_path / "docs" / "agent-hooks.md").exists()


def test_install_agent_hooks_writes_runtime_configs(tmp_path: Path) -> None:
    code = main(["install-agent-hooks", "--target", str(tmp_path), "--tool", "all"])
    assert code == 0
    assert (tmp_path / "scripts" / "security" / "agent_hook_runner.py").exists()
    codex_hooks = tmp_path / ".codex" / "hooks.json"
    assert codex_hooks.exists()
    codex_data = json.loads(codex_hooks.read_text(encoding="utf-8"))
    assert codex_data["hooks"]["PreToolUse"][0]["matcher"] == "Bash"
    assert "--profile sensitive-preflight" in codex_data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]

    claude_settings = tmp_path / ".claude" / "settings.json"
    assert claude_settings.exists()
    claude_data = json.loads(claude_settings.read_text(encoding="utf-8"))
    claude_args = claude_data["hooks"]["PreToolUse"][0]["hooks"][0]["args"]
    assert claude_args[-2:] == ["--profile", "sensitive-preflight"]

    opencode_plugin = tmp_path / ".opencode" / "plugins" / "ai-repo-safety.js"
    assert opencode_plugin.exists()
    opencode_text = opencode_plugin.read_text(encoding="utf-8")
    assert '"tool.execute.before"' in opencode_text
    assert "--profile sensitive-preflight" in opencode_text

    antigravity_hooks = tmp_path / ".agents" / "hooks.json"
    assert antigravity_hooks.exists()
    antigravity_data = json.loads(antigravity_hooks.read_text(encoding="utf-8"))
    assert antigravity_data["hooks"]["PreToolUse"][0]["matcher"] == "Bash"


def test_install_agent_hooks_for_single_runtime_scopes_output(tmp_path: Path) -> None:
    code = main(["install-agent-hooks", "--target", str(tmp_path), "--tool", "opencode"])
    assert code == 0
    assert (tmp_path / ".opencode" / "plugins" / "ai-repo-safety.js").exists()
    assert not (tmp_path / ".codex" / "hooks.json").exists()
    assert not (tmp_path / ".claude" / "settings.json").exists()
    assert not (tmp_path / ".agents" / "hooks.json").exists()


def test_setup_plan_does_not_mutate(tmp_path: Path) -> None:
    """Plan-only setup is strictly read-only: it must not create
    files, install hooks, or call any GitHub API. CI must be able
    to run this test on a machine with no network, no gh auth, and
    missing optional scanners."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True)
    code = main(["setup", "--target", str(tmp_path), "--python", "yes", "--github", "no"])
    assert code == 0, "plan-only setup must always succeed on a clean checkout"
    # Read-only contract: no files were created.
    assert not (tmp_path / ".gitignore").exists(), (
        "plan-only setup must not write .gitignore; that is init's job"
    )
    assert not (tmp_path / "AGENTS.md").exists()
    assert not (tmp_path / ".env.example").exists()
    assert not (tmp_path / "scripts" / "security" / "forbid_sensitive_files.py").exists()
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


def test_setup_apply_with_yes_writes_assets(tmp_path: Path) -> None:
    """Apply mode with --yes and --run-hooks actually mutates: it
    runs init and installs the pre-push hook."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True)
    code = main([
        "setup",
        "--target", str(tmp_path),
        "--python", "yes",
        "--github", "no",
        "--apply",
        "--run-hooks",
        "--yes",
    ])
    assert code == 0
    assert (tmp_path / ".gitignore").exists()
    assert (tmp_path / "AGENTS.md").exists()
    assert (tmp_path / ".git" / "hooks" / "pre-push").exists()

