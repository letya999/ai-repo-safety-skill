from __future__ import annotations

import json
from pathlib import Path

from .util import asset_text, project_root, write_text

SUPPORTED_TOOLS = ("codex", "claude", "opencode", "antigravity")


def _copy_runtime_assets(root: Path, *, overwrite: bool = False) -> list[str]:
    actions: list[str] = []
    assets = [
        ("scripts/agent_hook_runner.py", "scripts/security/agent_hook_runner.py"),
        ("docs/agent-hooks.md", "docs/agent-hooks.md"),
    ]
    for asset, dest in assets:
        if write_text(root / dest, asset_text(asset), overwrite=overwrite):
            actions.append(f"created {dest}")
        else:
            actions.append(f"kept existing {dest}")
    return actions


def _codex_hooks_json() -> str:
    payload = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python scripts/security/agent_hook_runner.py --profile sensitive-preflight",
                            "statusMessage": "Running repo safety preflight",
                        },
                    ],
                }
            ]
        }
    }
    return json.dumps(payload, indent=2) + "\n"


def _claude_settings_json() -> str:
    payload = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python",
                            "args": [
                                "${CLAUDE_PROJECT_DIR}/scripts/security/agent_hook_runner.py",
                                "--profile",
                                "sensitive-preflight",
                            ],
                        },
                    ],
                }
            ]
        }
    }
    return json.dumps(payload, indent=2) + "\n"


def _opencode_plugin_js() -> str:
    return """export const AiRepoSafetyPlugin = async ({ $ }) => {
  const runProfile = async (command) => {
    if (!command) return
    await $`python scripts/security/agent_hook_runner.py --profile sensitive-preflight --command ${command}`
  }

  return {
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash") return
      const command = output?.args?.command || input?.args?.command || ""
      await runProfile(command)
    },
  }
}
"""


def _antigravity_hooks_json() -> str:
    payload = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python scripts/security/agent_hook_runner.py --profile sensitive-preflight",
                            "statusMessage": "Running repo safety preflight",
                        },
                    ],
                }
            ]
        }
    }
    return json.dumps(payload, indent=2) + "\n"


def _tool_targets(root: Path, tool: str) -> list[tuple[Path, str]]:
    if tool == "codex":
        return [(root / ".codex" / "hooks.json", _codex_hooks_json())]
    if tool == "claude":
        return [(root / ".claude" / "settings.json", _claude_settings_json())]
    if tool == "opencode":
        return [(root / ".opencode" / "plugins" / "ai-repo-safety.js", _opencode_plugin_js())]
    if tool == "antigravity":
        return [(root / ".agents" / "hooks.json", _antigravity_hooks_json())]
    raise ValueError(f"unsupported tool: {tool}")


def install_agent_hooks(
    target: str | Path,
    *,
    tool: str = "all",
    overwrite: bool = False,
) -> int:
    root = project_root(target)
    requested = SUPPORTED_TOOLS if tool == "all" else (tool,)
    invalid = [name for name in requested if name not in SUPPORTED_TOOLS]
    if invalid:
        print(f"[repo-safety] unsupported tool(s): {', '.join(invalid)}")
        return 2

    actions = _copy_runtime_assets(root, overwrite=overwrite)
    pending_writes: list[tuple[Path, str]] = []
    for name in requested:
        pending_writes.extend(_tool_targets(root, name))

    conflicts = [path for path, _ in pending_writes if path.exists() and not overwrite]
    if conflicts:
        print("[repo-safety] refusing to overwrite existing agent hook config(s):")
        for path in conflicts:
            print(f"  - {path}")
        print("  Re-run with --overwrite to replace them.")
        return 4

    for path, content in pending_writes:
        write_text(path, content, overwrite=True)
        actions.append(f"installed {path.relative_to(root)}")

    print("AI Repo Safety agent hooks installed:")
    for action in actions:
        print(f"- {action}")
    return 0
