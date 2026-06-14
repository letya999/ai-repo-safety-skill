#!/usr/bin/env sh
set -eu
if ! command -v uv >/dev/null 2>&1; then
  echo "uv is missing. Install from official Astral docs, then rerun."
  exit 2
fi
uv sync
uv run ai-repo-safety doctor --agent-plan
echo "Optional: uv run ai-repo-safety install-missing"
