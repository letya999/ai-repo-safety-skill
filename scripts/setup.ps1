$ErrorActionPreference = "Stop"
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  Write-Host "uv is missing. Install from official Astral docs, then rerun."
  exit 2
}
uv sync
uv run ai-repo-safety doctor --agent-plan
Write-Host "Optional: uv run ai-repo-safety install-missing"
