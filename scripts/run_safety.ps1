$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location "$ScriptDir\.."

try {
    # Run the local python module using uv
    uv run ai-repo-safety $args
} finally {
    Pop-Location
}
