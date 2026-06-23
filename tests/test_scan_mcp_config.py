from __future__ import annotations

import json
import subprocess  # nosec
import sys
from pathlib import Path


SCRIPT = Path("scripts/security/scan_mcp_config.py").resolve()


def test_scan_mcp_config_flags_plaintext_scope_and_unpinned_runner(tmp_path: Path) -> None:
    token = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "servers": {
                    "github": {
                        "command": "npx @modelcontextprotocol/server-github",
                        "token": token,
                        "scopes": ["read", "write"],
                    }
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(  # nosec
        [sys.executable, str(SCRIPT)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 1
    assert "token-like credential without expiry/rotation metadata" in proc.stdout
    assert "over-privileged scope `write`" in proc.stdout
    assert "unpinned npx package invocation" in proc.stdout


def test_scan_mcp_config_accepts_pinned_read_only_logged_config(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        """{
  "servers": {
    "github-readonly": {
      "command": ["uvx", "my-mcp-server==1.2.3", "--audit-log", "./logs/mcp-audit.jsonl"],
      "scopes": ["read"],
      "expires_at": "2026-06-30T00:00:00Z"
    }
  }
}
""",
        encoding="utf-8",
    )
    proc = subprocess.run(  # nosec
        [sys.executable, str(SCRIPT)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_scan_mcp_config_does_not_require_audit_hint_for_read_only_config(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(
        """{
  "servers": {
    "github-readonly": {
      "command": ["uvx", "my-mcp-server==1.2.3"],
      "scopes": ["read"],
      "expires_at": "2026-06-30T00:00:00Z"
    }
  }
}
""",
        encoding="utf-8",
    )
    proc = subprocess.run(  # nosec
        [sys.executable, str(SCRIPT)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
