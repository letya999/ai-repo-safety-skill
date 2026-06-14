# AI Repo Safety Skill

One powerful public skill + asset repository for hardening AI/vibe-coded projects before commit, before push, and before publishing on GitHub.

The project is designed for **Python 3.12**, **uv**, and **uvx**, and works on **Windows, macOS, and Linux**. It uses only free / open-source / community tools by default.

## What this gives you

- one installable skill: `skill/ai-repo-safety/SKILL.md`
- one Python CLI: `ai-repo-safety`
- safe repo bootstrap before the first commit
- secret file denylist
- Gitleaks / TruffleHog / detect-secrets integration
- Opengrep-first SAST profile, without Semgrep as a default dependency
- Python hardening via Bandit, Ruff, pip-audit, pytest, pydantic-settings examples
- GitHub public repo hardening workflows
- GitHub read guard for commits, PRs, branches, issues, and merge request aliases
- MCP config safety checks
- lightweight STRIDE threat model templates
- incident cleanup templates
- cross-platform tool doctor and install plan

## Quick start from source

```bash
uv sync
uv run ai-repo-safety doctor
uv run ai-repo-safety init --target ../your-project --python auto --github auto
uv run ai-repo-safety install-hooks --target ../your-project
uv run ai-repo-safety scan --target ../your-project
```



## Quick start with uvx from a published Git repo

```bash
uvx --from git+https://github.com/YOUR_ORG/ai-repo-safety-skill ai-repo-safety doctor
uvx --from git+https://github.com/YOUR_ORG/ai-repo-safety-skill ai-repo-safety init --target . --python auto --github auto
uvx --from git+https://github.com/YOUR_ORG/ai-repo-safety-skill ai-repo-safety install-hooks --target .
uvx --from git+https://github.com/YOUR_ORG/ai-repo-safety-skill ai-repo-safety scan --target .
```

## Skill install layout

The skill lives here:

```text
SKILL.md
```

You can use the provided wrappers in `scripts/` to easily run the CLI.

## Commands

```bash
ai-repo-safety doctor
ai-repo-safety init --target . --python auto --github auto
ai-repo-safety install-hooks --target .
ai-repo-safety scan --target .
ai-repo-safety prepush --target .
ai-repo-safety github-guard read --target . --repo owner/repo --resource pulls --reason "review current PRs"
ai-repo-safety github-guard check-text --target . --file suspicious_issue.md
ai-repo-safety threat-model --target .
ai-repo-safety incident --target . --type secret-leak
```

## Tool philosophy

Default tools are free / OSS / community:

- `pre-commit`
- `gitleaks`
- `trufflehog`
- `detect-secrets`
- `opengrep`
- `bandit`
- `ruff`
- `pip-audit`
- `osv-scanner`
- `cyclonedx-py`
- `Renovate`
- `OpenSSF Scorecard`
- optional `CodeQL` for public/open-source GitHub repos

Semgrep is **not** the default. The SAST profile is Opengrep-first. Existing Semgrep-compatible rules can be adapted by the agent when compatible.

## Tool installation policy

The CLI checks whether Git, Python, uv, uvx, GitHub CLI, and scanners are available. It does not silently install system tools by default.

When tools are missing, the CLI produces an agent install plan. The agent must:

1. search official documentation or releases for the current stable compatible version,
2. select the install method for the detected OS,
3. install the tool only after the user or automation policy allows it,
4. re-run `ai-repo-safety doctor`,
5. continue only when required gates are available.

Python tools can usually be installed with `uv tool install ...`. System binaries such as Git, Gitleaks, TruffleHog, OSV-Scanner, and GitHub CLI may require OS package managers or official releases.

## GitHub read guard

Agents often ingest too much GitHub context: commits, PRs, branches, issues, comments, and public issue bodies with prompt injection. This project includes a read guard:

```bash
ai-repo-safety github-guard read --repo owner/repo --resource issues --reason "triage current issues"
```

It enforces policy from `.repo-safety.json`:

- only allowed repositories by default
- explicit reason required
- max items
- max body characters
- secret redaction
- prompt-injection pattern detection
- aliases for `mrs` / `merge_requests` -> GitHub pulls

Agents should use this wrapper instead of direct `gh api`, `gh pr view`, `gh issue view`, or raw GitHub web reads when reading GitHub context into an AI session.

## Important limits

This project gives strong local deterministic gates, but it cannot magically intercept every external AI tool. The included `AGENTS.md` and hook templates force agents to use the guardrails, but each client has different hook/plugin support.

The safe default is: if the agent cannot enforce a guardrail in its runtime, it must run the CLI guard before the risky action.
