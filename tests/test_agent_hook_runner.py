from __future__ import annotations

import os
import json
import subprocess  # nosec
import sys
from pathlib import Path

from ai_repo_safety.cli import main
from ai_repo_safety.assets.scripts.agent_hook_runner import opengrep_command, trufflehog_command


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


def test_mcp_audit_blocks_write_capable_gitlab_tool_and_logs(tmp_path: Path) -> None:
    main(["install-agent-hooks", "--target", str(tmp_path), "--tool", "codex"])
    script = tmp_path / "scripts" / "security" / "agent_hook_runner.py"
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__gitlab__create_merge_request_note",
        "tool_input": {"project": "group/repo", "mr_iid": 7, "body": "ship it"},
        "cwd": str(tmp_path),
    }
    proc = subprocess.run(  # nosec
        [sys.executable, str(script), "--profile", "mcp-invocation-audit"],
        cwd=tmp_path,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 2
    assert "blocking write-capable MCP tool call" in proc.stderr
    audit_log = tmp_path / ".repo-safety" / "logs" / "mcp-audit.jsonl"
    assert audit_log.exists()
    lines = audit_log.read_text(encoding="utf-8").splitlines()
    assert lines
    record = json.loads(lines[-1])
    assert record["tool_name"] == "mcp__gitlab__create_merge_request_note"
    assert record["decision"] == "deny"


def test_mcp_audit_allows_allowlisted_write_tool(tmp_path: Path) -> None:
    main(["install-agent-hooks", "--target", str(tmp_path), "--tool", "codex"])
    (tmp_path / ".repo-safety.json").write_text(
        json.dumps(
            {
                "mcp_policy": {
                    "audit_log": ".repo-safety/logs/mcp-audit.jsonl",
                    "allow_write_tools": ["mcp__gitlab__create_merge_request_note"],
                }
            }
        ),
        encoding="utf-8",
    )
    script = tmp_path / "scripts" / "security" / "agent_hook_runner.py"
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__gitlab__create_merge_request_note",
        "tool_input": {"project": "group/repo", "mr_iid": 7, "body": "ship it"},
        "cwd": str(tmp_path),
    }
    proc = subprocess.run(  # nosec
        [sys.executable, str(script), "--profile", "mcp-invocation-audit"],
        cwd=tmp_path,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


def test_mcp_audit_allows_read_style_gitlab_tool_with_note_noun(tmp_path: Path) -> None:
    main(["install-agent-hooks", "--target", str(tmp_path), "--tool", "codex"])
    script = tmp_path / "scripts" / "security" / "agent_hook_runner.py"
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__gitlab__get_merge_request_note",
        "tool_input": {"project": "group/repo", "mr_iid": 7, "note_id": 11},
        "cwd": str(tmp_path),
    }
    proc = subprocess.run(  # nosec
        [sys.executable, str(script), "--profile", "mcp-invocation-audit"],
        cwd=tmp_path,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    audit_log = tmp_path / ".repo-safety" / "logs" / "mcp-audit.jsonl"
    record = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[-1])
    assert record["decision"] == "observe"


def test_opengrep_command_excludes_repo_rule_definitions(tmp_path: Path) -> None:
    rules_dir = tmp_path / ".repo-safety" / "opengrep"
    rules_dir.mkdir(parents=True)
    cmd = opengrep_command(tmp_path)
    assert cmd is not None
    assert "--exclude" in cmd
    assert "src/ai_repo_safety/assets/rules/opengrep/" in cmd


def test_trufflehog_command_disables_self_update(tmp_path: Path) -> None:
    cmd = trufflehog_command(tmp_path)
    assert "--no-update" in cmd
