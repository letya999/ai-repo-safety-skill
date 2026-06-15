---
name: ai-repo-safety
description: Secure bootstrap and guardrails for AI/vibe-coded repositories. Applies OSS secret scanning, Opengrep-first SAST, Python hardening, GitHub read guard, MCP safety, supply-chain audit, threat-model-lite, and incident cleanup. Use before coding, before commit, before push, before reading GitHub context, and before publishing a repo.
---

# AI Repo Safety

You are applying one powerful universal safety skill to a repository. Your job is not to give generic advice. Your job is to bring the assets, adapt them to the repo, install hooks, run scanners, fix obvious findings, and report what remains.

## Default stack

- Python 3.12+
- uv / uvx
- Git
- Free / OSS / community tools only by default
- Opengrep-first SAST, not Semgrep-first
- GitHub profile only when GitHub is detected or requested

## When to use

Use this skill proactively when the user asks to:

- create a new project
- initialize a repo
- make a repo public
- push code
- add GitHub Actions
- add AI agent rules
- add MCP servers
- scan for secrets
- fix security posture
- review GitHub issues/PRs/commits/branches with an AI agent
- prepare a Python project for public GitHub
- clean up an exposed secret

## Installation

To run `ai-repo-safety` from any directory, install it as a tool using `uv`:

```bash
uv tool install --editable <path-to-ai-repo-safety-skill>
```

Alternatively, you can run it directly from its directory by passing the target path:

```bash
uv run ai-repo-safety <command> --target <path-to-target-repo>
```

## Workflow

1. Run environment check:

   ```bash
   uv run ai-repo-safety doctor --agent-plan
   ```

2. If Git, Python 3.12, uv, or uvx are missing:
   - search official docs or official releases for the current stable compatible version,
   - install using trusted OS package manager or official installer,
   - re-run doctor,
   - do not proceed with repo changes until required tooling exists.

3. Initialize safety assets:

   ```bash
   uv run ai-repo-safety init --target . --python auto --github auto
   ```

4. Install local hooks:

   ```bash
   uv run ai-repo-safety install-hooks --target .
   pre-commit install
   ```

5. Run scans:

   ```bash
   uv run ai-repo-safety scan --target .
   ```

6. Fix obvious issues:
   - move secrets to env variables,
   - create `.env.example` placeholders,
   - remove tracked secret files,
   - fix unsafe Python patterns,
   - remove unsafe MCP config,
   - replace hallucinated dependencies.

7. Before push:

   ```bash
   uv run ai-repo-safety prepush --target .
   ```

8. Before reading GitHub issues, PRs, commits, branches, or merge request aliases into AI context:

   ```bash
   uv run ai-repo-safety github-guard read --repo owner/repo --resource pulls --reason "review current PRs"
   ```

## Tooling behavior

- The `ai-repo-safety install-tools` command defaults to dry-run (`--plan`). To actually install system tools, you must explicitly pass `--yes`.
- The NPM wrapper uses a pinned `uvx` resolution for supply-chain safety.
- The CLI version is dynamically derived from `importlib.metadata` (the installed wheel).

## OpenCode flow & Threat Model

When operating on OpenCode repositories, follow the specific flow documented in `docs/opencode.md`. This workflow adheres to the agentic-skills threat model, ensuring secure automated changes and strict review gates for mutations.

## Practices this skill enforces

- Secure bootstrap before first commit
- `.gitignore` + `.env.example`, but no trust in `.gitignore` as a security boundary
- denylist for `.env`, keys, credentials, `.mcp.json`, `*.ovpn`
- Gitleaks / TruffleHog / detect-secrets gates
- Opengrep-compatible SAST rules
- Bandit / Ruff / pip-audit for Python
- OSV-Scanner / Renovate / SBOM templates for supply-chain audit
- GitHub Actions workflows for public repo hygiene
- GitHub read guard for commits, PRs, branches, issues, and MR aliases
- AGENTS.md rules for AI agents
- MCP allowlist and plaintext token checks
- lightweight STRIDE threat model
- incident cleanup flow: rotate first, then clean history

## Safety rules

Never read, print, upload, summarize, or commit:

- `.env`, `.env.*`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`
- `id_rsa`, `id_ed25519`
- `credentials*.json`, `service-account*.json`
- `token.json`, `tokens.json`, `secrets.json`
- `.mcp.json`, `claude_desktop_config.json`
- `*.ovpn`

Never do without explicit user confirmation:

- `git push`
- make repository public
- create public issue/PR with private context
- read GitHub issues/PRs/commits/branches directly into AI context
- run `env`, `printenv`, `cat .env`, `Get-Content .env`
- install unknown packages suggested only by model memory
- add or change MCP servers
- disable auth/RLS/CORS/security checks just to make code work

## Missing tools policy

If a tool is missing, do not invent stale install commands from memory. Run doctor, then search official docs/releases for the current stable compatible version. Prefer:

- `uv tool install ...` for Python tools
- official releases or trusted OS package managers for system binaries
- pinned versions where possible

## Output format after applying

Report:

- files added/changed
- tools missing
- scans run
- findings fixed
- findings left for user review
- exact next commands
