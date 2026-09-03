# Tooling model

Canonical invoke:

```text
py -3 -m ai_repo_safety <cmd> --target .
python -m ai_repo_safety <cmd> --target .
uvx ai-repo-safety <cmd> --target .
```

Required runtime tools (verified by `ai-repo-safety doctor --target .`):

- Git
- Python 3.12+
- uv
- uvx

Commit/push/tag hardness is `python -m ai_repo_safety gate --when commit|push|tag`.
Tag gates audit `uv.lock` via osv-scanner (fallback: `uv export --frozen --no-dev` + `pip-audit -r --disable-pip`). Never run bare `pip-audit` against the CLI interpreter.

## How tools get installed

`ai-repo-safety install-missing` (alias for the newer
`ai-repo-safety install-tools` command) splits the work between
read-only detection and explicit mutations:

- `doctor` and `install-tools --plan` only print what would happen.
- `install-tools --yes` is required for any actual install.
- Python helper tools go through `uv tool install` automatically.
- System tools (gitleaks, trufflehog, opengrep, osv-scanner, gh)
  need an explicit package manager; the agent must search
  official docs for the current stable compatible version.

System tools are **never** silently installed by the CLI. The
command refuses to run unless the user has passed `--yes` and the
target package manager is supported on the host.

## Direct binary downloads

`trufflehog` is the only tool that historically came from a direct
GitHub release download on Windows. That path is gated behind an
explicit `--allow-download` and prints the version and SHA-256 it
is about to fetch. The skill requires the agent to verify the
checksum against the release notes before installation.

## Why this discipline

Install commands for these tools change by OS, CPU architecture,
and current release packaging. The skill forces the agent to
verify current stable docs instead of using stale commands from
model memory. Stale curl|bash snippets are an attack surface that
this project explicitly refuses to use as a default.
