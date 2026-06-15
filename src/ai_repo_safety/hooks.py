from __future__ import annotations

import stat
from pathlib import Path

from .util import project_root, write_text

# Public marker delimiting the block of the pre-push hook that
# ai-repo-safety manages. The two non-ascii character classes are
# deliberately chosen so they are extremely unlikely to collide with
# any pre-existing hook an end user wrote by hand.
PRE_PUSH_MARKER = "AI REPO SAFETY PRE-PUSH"
PRE_PUSH_POSIX = '''#!/usr/bin/env sh
# >>> AI REPO SAFETY PRE-PUSH >>>
set -eu
if command -v ai-repo-safety >/dev/null 2>&1; then
  ai-repo-safety prepush --target .
elif command -v uv >/dev/null 2>&1 && [ -f pyproject.toml ]; then
  uv run ai-repo-safety prepush --target .
elif command -v uvx >/dev/null 2>&1; then
  uvx ai-repo-safety prepush --target .
elif [ -f scripts/security/prepush.py ]; then
  python scripts/security/prepush.py
else
  echo "[repo-safety] ai-repo-safety not found; refusing push"
  exit 1
fi
# <<< AI REPO SAFETY PRE-PUSH <<<
'''

PRE_PUSH_WINDOWS = '''@echo off
rem >>> AI REPO SAFETY PRE-PUSH >>>
where ai-repo-safety >nul 2>nul
if %ERRORLEVEL%==0 (
  ai-repo-safety prepush --target .
  exit /b %ERRORLEVEL%
)
where uv >nul 2>nul
if %ERRORLEVEL%==0 if exist pyproject.toml (
  uv run ai-repo-safety prepush --target .
  exit /b %ERRORLEVEL%
)
where uvx >nul 2>nul
if %ERRORLEVEL%==0 (
  uvx ai-repo-safety prepush --target .
  exit /b %ERRORLEVEL%
)
if exist scripts\\security\\prepush.py (
  python scripts\\security\\prepush.py
  exit /b %ERRORLEVEL%
)
echo [repo-safety] ai-repo-safety not found; refusing push
exit /b 1
rem <<< AI REPO SAFETY PRE-PUSH <<<
'''


def _has_marker(text: str) -> bool:
    return PRE_PUSH_MARKER in text


def _strip_managed_block(text: str) -> str:
    """Remove a previously-installed managed block, leaving any
    user-authored content around it intact."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_block = False
    for line in lines:
        if ">>> " + PRE_PUSH_MARKER + " >>>" in line:
            in_block = True
            continue
        if "<<< " + PRE_PUSH_MARKER + " <<<" in line:
            in_block = False
            continue
        if not in_block:
            out.append(line)
    return "".join(out).rstrip() + "\n"


def install_hooks(
    target: str | Path,
    *,
    overwrite: bool = False,
    chain: bool = False,
    hooks_path: str | None = None,
) -> int:
    """Install the ai-repo-safety pre-push hook.

    Default behavior is safe: refuse to overwrite a pre-existing
    unmanaged hook (exit 4). The caller can opt in to chaining
    (append a managed block after the existing content) or
    overwriting (replace the file with the managed hook).
    """
    root = project_root(target)
    if hooks_path:
        hooks_dir = root / hooks_path
    else:
        git_dir = root / ".git"
        if not git_dir.exists():
            print("[repo-safety] .git directory not found. Initialize Git first: git init")
            return 2
        hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    posix = hooks_dir / "pre-push"
    cmd = hooks_dir / "pre-push.cmd"

    for path, content in [(posix, PRE_PUSH_POSIX), (cmd, PRE_PUSH_WINDOWS)]:
        if path.exists():
            existing = path.read_text(encoding="utf-8", errors="replace")
            if _has_marker(existing):
                # Refresh the managed block in place.
                stripped = _strip_managed_block(existing).rstrip() + "\n\n" + content
                path.write_text(stripped, encoding="utf-8")
                print(f"[repo-safety] updated managed block in {path}")
                continue
            if not overwrite and not chain:
                print(
                    f"[repo-safety] refusing to overwrite existing unmanaged hook: {path}\n"
                    f"  Re-run with --chain to keep the existing hook and append the\n"
                    f"  managed block, or with --overwrite to replace it."
                )
                return 4
            if chain:
                # Keep the existing content and append the managed
                # block after a blank line.
                appended = existing.rstrip() + "\n\n" + content
                path.write_text(appended, encoding="utf-8")
                print(f"[repo-safety] chained managed block after {path}")
                continue
        # Either file does not exist or --overwrite was passed.
        write_text(path, content, overwrite=True)
        print(f"[repo-safety] installed {path}")

    # Make the POSIX hook executable.
    if posix.exists():
        current = posix.stat().st_mode
        posix.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print("[repo-safety] For pre-commit hooks run: pre-commit install")
    return 0
