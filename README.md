# AI Repo Safety Skill

[![skills.sh](https://skills.sh/b/letya999/ai-repo-safety-skill)](https://skills.sh/letya999/ai-repo-safety-skill)
[![PyPI](https://img.shields.io/pypi/v/ai-repo-safety)](https://pypi.org/project/ai-repo-safety/)
[![npm](https://img.shields.io/npm/v/ai-repo-safety)](https://www.npmjs.com/package/ai-repo-safety)

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

## Install the skill (AI agents)

Install to all detected agents in one command:

```bash
npx skills add letya999/ai-repo-safety-skill
```

Or install to a specific agent:

```bash
npx skills add letya999/ai-repo-safety-skill -a claude-code
```

## Install the CLI

Package pages:

- npm: [https://www.npmjs.com/package/ai-repo-safety](https://www.npmjs.com/package/ai-repo-safety)
- PyPI: [https://pypi.org/project/ai-repo-safety/](https://pypi.org/project/ai-repo-safety/)

**Via uv/uvx (recommended):**

```bash
uv tool install ai-repo-safety
ai-repo-safety doctor
```

Or run without installing:

```bash
uvx ai-repo-safety doctor
uvx ai-repo-safety init --target . --python auto --github auto
uvx ai-repo-safety scan --target .
```

**Via pip:**

```bash
pip install ai-repo-safety
ai-repo-safety doctor
```

**Via npm (delegates to Python under the hood):**

```bash
npm install -g ai-repo-safety
ai-repo-safety doctor
```

## Skill install layout

The skill lives here:

```text
SKILL.md
```

The skill is ready to be executed via `uv run` universally on Windows, macOS, and Linux without the need for OS-specific shell wrappers.

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

## AI Assistant Integrations

To ensure your AI assistants (like Claude Code, Codex, OpenCode, and Cursor) follow these repository safety rules, you can integrate this skill using the following steps:

### 1. Installing via `skills` CLI
If you use a `skills` manager or custom CLI tool for orchestrating agent abilities, install the skill directly:
```bash
skills add git+https://github.com/letya999/ai-repo-safety-skill
```
This will place the `SKILL.md` and related guardrails into your agent workspace.

### 2. Integration with AI Assistants & IDEs

#### Claude Code (by Anthropic)
Claude Code automatically scans and respects repository instructions. To make it aware of this safety skill:
1. Place [AGENTS.md](AGENTS.md) in the root of your project directory.
2. When starting a session, Claude Code reads root markdown instructions (like `AGENTS.md`) and strictly adheres to the forbidden actions and GitHub read guard policies.
3. You can also reference the CLI directly in your prompt to enforce checks, e.g., `claude "run ai-repo-safety scan before committing"`.

#### Codex CLI & OpenCode
For CLI-based agents:
1. Inject the rules by importing the skill or placing the `SKILL.md` in your agent's config folder.
2. The agent will read `SKILL.md` as part of its system instructions, preventing it from performing direct `git push` or reading raw GitHub API responses without using `ai-repo-safety github-guard`.

#### Cursor (IDE)
Cursor uses `.cursorrules` to guide its Chat and Composer features:
1. Create a `.cursorrules` file in the root of your repository (if it doesn't exist yet).
2. Copy the content of [AGENTS.md](AGENTS.md) into your `.cursorrules` file or append a reference:
   ```markdown
   Always follow the repository safety guardrails defined in AGENTS.md.
   Never run forbidden actions (like git push, public PR creation) without user confirmation.
   ```
3. Cursor's AI will automatically prioritize these instructions during code generation and terminal executions.

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

The CLI checks whether Git, Python, uv, uvx, GitHub CLI, and scanners are available. 

When tools are missing, the agent can automatically install all required Python and System binaries by running:
```bash
uv run ai-repo-safety install-missing
```

This command uses `uv tool` for Python tools (like bandit, pip-audit) and leverages the native package manager (`winget`, `brew`, `npm`) or direct downloads to globally install system binaries (like Gitleaks, OSV-Scanner, TruffleHog, Opengrep, GitHub CLI) across Windows, macOS, and Linux.

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
