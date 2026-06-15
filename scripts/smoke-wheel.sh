#!/usr/bin/env sh
# Installed-wheel smoke for ai-repo-safety.
#
# Builds the current source tree with `uv build`, installs the wheel
# into a fresh venv with no network, runs the CLI end to end, and
# verifies that the asset-driven init produces every file the
# templates are supposed to emit. This is the catch-net for the D0
# regression class (assets silently dropped from the distribution)
# that the v0.1.3 wheel shipped with.
#
# Exit non-zero on any failure. The script is intentionally
# self-contained: no CI runner assumptions beyond uv, python, and sh.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

rm -rf dist .tmp-smoke
uv build

python -m venv .tmp-smoke/venv
# shellcheck disable=SC1091
.tmp-smoke/venv/bin/pip install --quiet --no-index --find-links dist ai-repo-safety

.tmp-smoke/venv/bin/ai-repo-safety --version
.tmp-smoke/venv/bin/ai-repo-safety init --target .tmp-smoke/target --python yes --github no

test -f .tmp-smoke/target/AGENTS.md
test -f .tmp-smoke/target/SECURITY.md
test -f .tmp-smoke/target/bandit.yaml
test -f .tmp-smoke/target/pyproject.ai-repo-safety.toml
test -f .tmp-smoke/target/.repo-safety/opengrep/python-dangerous-code.yml
test -f .tmp-smoke/target/.repo-safety/opengrep/python-fastapi-security.yml
test -f .tmp-smoke/target/.repo-safety/opengrep/secrets-adjacent.yml
test -f .tmp-smoke/target/scripts/security/forbid_sensitive_files.py
test -f .tmp-smoke/target/scripts/security/scan_mcp_config.py
test -f .tmp-smoke/target/docs/mcp-safety.md
test -f .tmp-smoke/target/docs/threat-model.md

# Re-run init with --plan-style defaults and confirm setup is
# strictly read-only: no git hooks are installed.
.tmp-smoke/venv/bin/ai-repo-safety setup --target .tmp-smoke/target --python yes --github no

# Plan-only setup must not have installed a pre-push hook on the
# target tree (no .git/hooks/pre-push file there).
if [ -e .tmp-smoke/target/.git/hooks/pre-push ]; then
    echo "smoke-wheel.sh: FAIL: plan-only setup installed a pre-push hook" >&2
    exit 1
fi

echo "smoke-wheel.sh: OK"
