# Agent Hook MVP

This project can install a minimal project-local hook layer for the
major AI coding CLIs that currently expose official hook or plugin
surfaces:

- Grok
- Codex
- Claude Code
- OpenCode
- Antigravity CLI

Agent hooks are an early warning. They are **not** the lock: Grok
hooks fail open on timeout or crash. Fail-closed hardness lives in
`git` `pre-commit` / `pre-push` installed by `install-hooks`.

## Scope

The runner classifies the pending command and calls the matching
`gate --when` profile:

- `git commit` → commit (staged sensitive files + `gitleaks protect --staged`)
- `git push` → push (secrets + MCP + gitleaks + trufflehog)
- `git tag` / `git push --tags` → tag (push + lockfile audit)

It accepts both Codex `tool_input` and Grok `toolInput` payloads.
Empty Grok `toolInput` is a deny, not a skip.

For `Grok`, `Codex`, and `Claude Code`, the generated project hooks
also add an MCP invocation audit for `github__*` / `gitlab__*` and
`mcp__github__.*` / `mcp__gitlab__.*`. Those hooks:

1. append JSONL audit records to `.repo-safety/logs/mcp-audit.jsonl`
2. allow read-style tools
3. block write-capable GitHub/GitLab MCP tools by default unless the
   repo explicitly allowlists them in `.repo-safety/config.json`

The generated hooks run **only** before sensitive commands such as:

- `git commit`
- `git push`
- `git tag`
- `gh pr create`
- `npm publish`
- `uv publish`
- `twine upload`

If the pending command is not in this class, the hook exits quickly
without running scanners.

## Install

```bash
python -m ai_repo_safety install-agent-hooks --target . --tool all
```

Or limit installation to one runtime:

```bash
python -m ai_repo_safety install-agent-hooks --target . --tool grok
python -m ai_repo_safety install-agent-hooks --target . --tool codex
python -m ai_repo_safety install-agent-hooks --target . --tool claude
python -m ai_repo_safety install-agent-hooks --target . --tool opencode
python -m ai_repo_safety install-agent-hooks --target . --tool antigravity
```

Grok project hooks stay silent until you run `/hooks-trust` in the
repo. They are not installed into `~/.grok/hooks/` unless you pass
`--global`.

## Generated files

```text
.repo-safety/scripts/agent_hook_runner.py
docs/agent-hooks.md
.grok/hooks/ai-repo-safety.json
.codex/hooks.json
.claude/settings.json
.opencode/plugins/ai-repo-safety.js
.agents/hooks.json
```

## Runtime Matrix

| Runtime | Project-local entrypoint | How it is discovered | Activation notes |
| --- | --- | --- | --- |
| Grok | `.grok/hooks/ai-repo-safety.json` | Grok merges project `.grok/hooks/*.json` | Must run `/hooks-trust`. Matcher `Bash` aliases to `run_terminal_command`. Timeout 600s. Fail-open unless stdout is `{"decision":"deny"}` or exit 2. Do not install to `~/.grok/hooks/` by default |
| Codex | `.codex/hooks.json` | Codex reads project hooks from the repo `.codex/` layer alongside user/system layers | The project layer must be trusted; review via `/hooks` if Codex marks the hook as untrusted. The generated config includes `commandWindows` overrides for Windows and separate GitHub/GitLab MCP matcher groups |
| Claude Code | `.claude/settings.json` | Claude Code reads hooks under the `hooks` key from project settings | If the session is already open, reload or restart the session after changing the file. This runtime gets shell preflight plus MCP GitHub/GitLab audit |
| OpenCode | `.opencode/plugins/ai-repo-safety.js` | OpenCode auto-loads project plugins from `.opencode/plugins/` at startup | Restart or reload OpenCode if the project was already open before generation |
| Antigravity | `.agents/hooks.json` | Antigravity uses workspace/project customization under `.agents/` | Restart or reload the workspace so the runtime re-reads the workspace hook config. The generated config includes a Windows-specific command override |

## Project Scope

These hooks are intentionally **project-local**, not global:

- they travel with the repository
- they express repository policy rather than user preference
- different repositories can enforce different safety levels
- the same user can still keep stricter global hooks outside the repo

## Design notes

- The hook logic is centralized in `.repo-safety/scripts/agent_hook_runner.py`.
- The runner uses only the Python standard library so it can execute
  inside the local project without importing `ai_repo_safety`.
- `gitleaks` is mandatory in the preflight profile because a repo
  safety gate should not allow sensitive push/publish flows when the
  primary secret scanner is unavailable.
- `OpenCode` uses a small plugin wrapper because its extensibility
  surface is event-driven JavaScript rather than a standalone
  `hooks.json` file.
- `Codex`, `Claude Code`, and `Antigravity` use project-local config
  files that trigger a shell-command hook before sensitive commands.
- `Codex` and `Antigravity` emit `commandWindows` overrides so the
  generated hook stays usable on Windows without depending on shell
  path translation.
- The current MCP audit is intentionally narrower than the shell
  gate: it focuses on GitHub/GitLab MCP tools where delegated API
  actions are most likely to mutate external systems silently.

## MCP Policy

Optional repository policy in `.repo-safety/config.json`:

```json
{
  "mcp_policy": {
    "audit_log": ".repo-safety/logs/mcp-audit.jsonl",
    "allow_write_tools": [
      "mcp__gitlab__create_merge_request_note"
    ]
  }
}
```

- `audit_log`: overrides the default JSONL path
- `allow_write_tools`: regex patterns matched with `re.fullmatch`
  against the MCP tool name

## Limits

- This is a **minimal** gate, not a complete enforcement boundary.
- It covers shell-style sensitive operations, not every possible edit
  or network path.
- `gitleaks` and `trufflehog` are always part of the profile.
- `bandit` runs only when the repository looks like a Python project.
- `opengrep` runs only when the generated rules directory exists.
- `trufflehog` uses `git --since-commit` when possible and falls back
  to filesystem scanning on short or detached history.
