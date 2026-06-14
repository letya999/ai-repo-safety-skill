from __future__ import annotations

import stat
from pathlib import Path

from .util import project_root, write_text

PRE_PUSH_POSIX = '''#!/usr/bin/env sh
set -eu
if command -v ai-repo-safety >/dev/null 2>&1; then
  ai-repo-safety prepush --target .
elif command -v uvx >/dev/null 2>&1; then
  uvx ai-repo-safety prepush --target .
elif [ -f scripts/security/prepush.py ]; then
  python scripts/security/prepush.py
else
  echo "[repo-safety] ai-repo-safety not found; refusing push"
  exit 1
fi
'''

PRE_PUSH_WINDOWS = '''@echo off
where ai-repo-safety >nul 2>nul
if %ERRORLEVEL%==0 (
  ai-repo-safety prepush --target .
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
'''


def install_hooks(target: str | Path) -> int:
    root = project_root(target)
    git_dir = root / ".git"
    if not git_dir.exists():
        print("[repo-safety] .git directory not found. Initialize Git first: git init")
        return 2
    hooks = git_dir / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    posix = hooks / "pre-push"
    cmd = hooks / "pre-push.cmd"
    write_text(posix, PRE_PUSH_POSIX, overwrite=True)
    write_text(cmd, PRE_PUSH_WINDOWS, overwrite=True)
    current = posix.stat().st_mode
    posix.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"[repo-safety] installed {posix}")
    print(f"[repo-safety] installed {cmd}")
    print("[repo-safety] For pre-commit hooks run: pre-commit install")
    return 0
