# AGENTS.md — AI Repo Safety Rules

This repository uses AI Repo Safety git hooks as the fail-closed gates.

## Forbidden files to read, print, summarize, upload, or commit

Do not read or print these files unless the user explicitly confirms the security risk:

- `.env`, `.env.*`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`
- `id_rsa`, `id_ed25519`
- `credentials*.json`, `service-account*.json`
- `token.json`, `tokens.json`, `secrets.json`
- `.mcp.json`, `claude_desktop_config.json`
- `*.ovpn`

## Forbidden actions without explicit confirmation

- `git push` / pushing a tag
- making a repository public
- creating public issues or PRs with private context
- running `env`, `printenv`, `set`, `cat .env`, `type .env`, `Get-Content .env`
- adding or changing MCP servers
- disabling auth, RLS, CORS, input validation, TLS checks, or security scans just to make code work
- installing unknown packages suggested only by model memory

## GitHub context reads

Do not paste raw GitHub issue/PR/commit bodies into AI context. Use:

```text
python -m ai_repo_safety gate --when github-read --repo owner/repo --resource pulls --reason "review current PRs"
```

## Git gates

Commit, push, and tag are enforced by git hooks. If hooks are missing and you are about to commit or push:

```text
python -m ai_repo_safety gate --when commit --target .
python -m ai_repo_safety gate --when push --target .
python -m ai_repo_safety gate --when tag --target .
```
