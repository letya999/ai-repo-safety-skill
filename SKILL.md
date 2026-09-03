---
name: ai-repo-safety
description: Git-hook-backed secret and supply-chain gates for AI-coded repos. Use when initializing a repo, handling a leaked secret, making a public release, or when the user names this skill. Do not load just because a coding session started.
---

# AI Repo Safety

Canonical invoke:

```text
py -3 -m ai_repo_safety <cmd> --target .
python -m ai_repo_safety <cmd> --target .
uvx ai-repo-safety <cmd> --target .
```

Do not run `doctor`, `init`, or `scan` at the start of a session.

## Git gates (this is the lock)

Commit, push, and tag are enforced by git hooks, not by this file.

```text
python -m ai_repo_safety install-hooks --target .
```

If hooks are missing and you are about to `git commit` / `git push` / `git tag`:

```text
python -m ai_repo_safety gate --when commit --target .
python -m ai_repo_safety gate --when push --target .
python -m ai_repo_safety gate --when tag --target .
```

`--no-verify` is a human escape hatch. Do not use it to skip a finding.

## GitHub context

Do not pipe `gh pr view`, `gh issue view`, or raw GitHub pages into the model.

```text
python -m ai_repo_safety gate --when github-read --repo owner/repo --resource pulls --reason "review current PRs"
```

## Init (only when asked)

```text
python -m ai_repo_safety init --target .
python -m ai_repo_safety install-agent-hooks --target . --tool grok
```

Then run `/hooks-trust` so Grok project hooks load. Grok hooks fail open; git hooks stay fail-closed.

## Never

Do not read, print, or commit: `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_ed25519`, `credentials*.json`, `service-account*.json`, `token.json`, `tokens.json`, `secrets.json`, `.mcp.json`, `claude_desktop_config.json`, `*.ovpn`.

Do not `git push`, publish, make the repo public, or open a public PR unless the user asked.

## Incident

If a secret is found, stop and follow `docs/incident-cleanup.md`. Threat-model, GitLab, and OpenCode live in `docs/`.
