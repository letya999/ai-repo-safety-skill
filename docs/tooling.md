# Tooling model

Required runtime tools:

- Git
- Python 3.12+
- uv
- uvx

Python helper tools can be installed by the CLI with:

```bash
ai-repo-safety install-missing
```

This installs only Python tools through `uv tool install`:

- pre-commit
- detect-secrets
- bandit
- ruff
- pip-audit
- git-filter-repo

System tools are not silently installed by the CLI. If missing, the agent must search official docs/releases for current stable compatible versions and install through the OS package manager or official release:

- gitleaks
- trufflehog
- opengrep
- osv-scanner
- gh

Reason: install commands for these tools change by OS, CPU architecture, and current release packaging. The skill forces the agent to verify current stable docs instead of using stale commands from memory.
