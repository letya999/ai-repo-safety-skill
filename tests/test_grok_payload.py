from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ai_repo_safety.assets.scripts.agent_hook_runner import classify_when, extract_command
from ai_repo_safety.cli import main


def test_extract_command_reads_grok_camelcase() -> None:
    payload = {
        "hookEventName": "pre_tool_use",
        "toolName": "run_terminal_command",
        "toolInput": {"command": "git commit -m 'x'"},
    }
    assert extract_command(json.dumps(payload), None) == "git commit -m 'x'"
    assert classify_when("git commit -m 'x'") == "commit"


def test_extract_command_reads_codex_snake_case() -> None:
    payload = {"tool_name": "Bash", "tool_input": {"command": "git push origin dev"}}
    assert extract_command(json.dumps(payload), None) == "git push origin dev"
    assert classify_when("git push origin dev") == "push"


def test_empty_grok_command_does_not_skip(tmp_path: Path) -> None:
    main(["install-agent-hooks", "--target", str(tmp_path), "--tool", "grok"])
    script = tmp_path / ".repo-safety" / "scripts" / "agent_hook_runner.py"
    payload = {
        "hookEventName": "pre_tool_use",
        "toolName": "run_terminal_command",
        "toolInput": {},
    }
    proc = subprocess.run(
        [sys.executable, str(script), "--profile", "gate"],
        cwd=tmp_path,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 2
    decision = json.loads(proc.stdout.splitlines()[0])
    assert decision["decision"] == "deny"
    assert "could not parse command" in proc.stderr
