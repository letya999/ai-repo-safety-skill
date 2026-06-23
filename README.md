# AI Repo Safety Skill

Package links:

- skill: [https://skills.sh/letya999/ai-repo-safety-skill](https://skills.sh/letya999/ai-repo-safety-skill)
- PyPI: [https://pypi.org/project/ai-repo-safety/](https://pypi.org/project/ai-repo-safety/)
- npm: [https://www.npmjs.com/package/ai-repo-safety](https://www.npmjs.com/package/ai-repo-safety)

One powerful public skill + asset repository for hardening AI/vibe-coded projects before commit, before push, and before publishing on GitHub.

The project is designed for **Python 3.12**, **uv**, and **uvx**, and works on **Windows, macOS, and Linux**. It uses only free / open-source / community tools by default.

## What this gives you

- one installable skill: `SKILL.md`
- one Python CLI: `ai-repo-safety`
- safe repo bootstrap before the first commit
- secret file denylist
- Gitleaks / TruffleHog / detect-secrets integration
- Opengrep-first SAST profile, without Semgrep as a default dependency
- Python hardening via Bandit, Ruff, pip-audit, pytest, pydantic-settings examples
- GitHub public repo hardening workflows
- GitLab CI pipeline templates and SaaS/Self-Hosted config support
- GitHub and GitLab read guard for commits, PRs, branches, issues, and merge requests
- MCP config safety checks
- lightweight STRIDE threat model templates
- incident cleanup templates
- cross-platform tool doctor and install plan

> **Note:** Earlier versions of this README referenced
> `skill/ai-repo-safety/SKILL.md`. The skill ships as a single
> `SKILL.md` at the repository root, and agents are expected to
> install it into their config directory via the
> [skills](https://github.com/vercel-labs/skills) CLI.

## Install the skill (AI agents)

Install to all detected agents in one command:

```bash
npx skills add letya999/ai-repo-safety-skill
```

Or install to a specific agent:

```bash
npx skills add letya999/ai-repo-safety-skill -a claude-code
```

> **Branch and release model:** the default branch is `dev`.
> Releases are tagged from `dev` (e.g. `v0.1.6`) and published to
> PyPI and npm on tag push. PyPI uses Trusted Publishing; npm
> prefers Trusted Publishing but supports `NPM_TOKEN` fallback. The
> `ai-repo-safety verify-release --version X.Y.Z` command checks
> that a release is ready before you push the tag.

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
# Read-only environment check.
ai-repo-safety doctor

# Plan-only bootstrap. By default does not install tools, hooks,
# or call the GitHub API. Use --apply --yes and the matching
# opt-in flag to perform a specific mutation.
ai-repo-safety init --target . --python auto --github auto
ai-repo-safety setup --target .            # plan only
ai-repo-safety setup --target . --apply --run-hooks --yes

# Local hook install. Refuses to overwrite an unmanaged existing
# hook unless --overwrite (or --chain to append) is passed.
ai-repo-safety install-hooks --target .
ai-repo-safety install-hooks --target . --chain
ai-repo-safety install-hooks --target . --overwrite

# Project-local agent hooks. These are repo-scoped, not global:
# Codex reads .codex/hooks.json, Claude Code reads
# .claude/settings.json, OpenCode auto-loads .opencode/plugins/,
# Antigravity reads workspace .agents/hooks.json.
ai-repo-safety install-agent-hooks --target . --tool all

# Scans.
ai-repo-safety scan --target .
ai-repo-safety scan --target . --strict
ai-repo-safety prepush --target .

# GitHub read guard. Always pass an explicit --reason.
ai-repo-safety github-guard validate --target . --repo owner/repo --resource pulls --reason "review current PRs"
ai-repo-safety github-guard read --target . --repo owner/repo --resource pulls --reason "review current PRs"
ai-repo-safety github-guard check-text --target . --file suspicious_issue.md

# GitLab read guard for SaaS and Self-Hosted.
ai-repo-safety gitlab-guard read --target . --repo namespace/repo --resource merge_requests --reason "analyze MRs"

# Threat model and incident templates.
ai-repo-safety threat-model --target .
ai-repo-safety incident --target . --type secret-leak

# Pre-release verification.
ai-repo-safety verify-release --version 0.1.6 --target .
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

Agents should use this wrapper instead of direct `gh api`, `gh pr view`, `glab api`, `glab mr view`, or raw GitHub/GitLab web reads when reading context into an AI session.

## Important limits

This project gives strong local deterministic gates, but it cannot magically intercept every external AI tool. The included `AGENTS.md` and hook templates force agents to use the guardrails, but each client has different hook/plugin support.

The safe default is: if the agent cannot enforce a guardrail in its runtime, it must run the CLI guard before the risky action.
