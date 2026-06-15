"""Installed-artifact manifest check for ai-repo-safety.

Run after `uv build`. Verifies the wheel and sdist in dist/ contain
the asset templates the runtime CLI depends on. This is the
command form of the wheel-smoke shell script and is suitable for
CI runners that prefer Python over sh.
"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

REQUIRED_WHEEL_ASSETS: tuple[str, ...] = (
    "ai_repo_safety/assets/templates/universal/AGENTS.md",
    "ai_repo_safety/assets/templates/universal/SECURITY.md",
    "ai_repo_safety/assets/templates/universal/env.example",
    "ai_repo_safety/assets/templates/universal/gitignore.block",
    "ai_repo_safety/assets/templates/universal/pre-commit-config.yaml",
    "ai_repo_safety/assets/templates/python/bandit.yaml",
    "ai_repo_safety/assets/templates/python/pyproject.ai-repo-safety.toml",
    "ai_repo_safety/assets/templates/python/settings.py",
    "ai_repo_safety/assets/templates/python/test_security_basics.py",
    "ai_repo_safety/assets/scripts/forbid_sensitive_files.py",
    "ai_repo_safety/assets/scripts/prepush.py",
    "ai_repo_safety/assets/scripts/scan_mcp_config.py",
    "ai_repo_safety/assets/rules/opengrep/python-dangerous-code.yml",
    "ai_repo_safety/assets/rules/opengrep/github-actions-security.yml",
)


def _check_wheel(dist: Path) -> list[str]:
    whl = next(dist.glob("*.whl"), None)
    if whl is None:
        return ["missing wheel in dist/"]
    names = set(zipfile.ZipFile(whl).namelist())
    return [name for name in REQUIRED_WHEEL_ASSETS if name not in names]


def _check_sdist(dist: Path) -> list[str]:
    sdist = next(dist.glob("*.tar.gz"), None)
    if sdist is None:
        return ["missing sdist in dist/"]
    with tarfile.open(sdist) as tf:
        sdist_names = tf.getnames()
    missing: list[str] = []
    for req in REQUIRED_WHEEL_ASSETS:
        suffix = "/src/" + req
        if not any(name.endswith(suffix) for name in sdist_names):
            missing.append(req)
    return missing


def main() -> int:
    dist = Path("dist")
    if not dist.exists():
        print("dist/ does not exist; run `uv build` first", file=sys.stderr)
        return 2
    wheel_missing = _check_wheel(dist)
    sdist_missing = _check_sdist(dist)
    if wheel_missing:
        print("missing wheel assets:")
        for name in wheel_missing:
            print(f"  - {name}")
    if sdist_missing:
        print("missing sdist assets:")
        for name in sdist_missing:
            print(f"  - {name}")
    if wheel_missing or sdist_missing:
        return 1
    print("package artifact manifest: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
