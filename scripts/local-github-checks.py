"""Run local equivalents for this repo's GitHub Actions checks.

The GitHub workflows contain a mix of deterministic commands and
GitHub-hosted checks. This runner executes the deterministic checks
locally and prints an explicit note for checks that require GitHub event
or security-events context.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Check:
    name: str
    command: Sequence[str] | None = None
    note: str | None = None
    optional: bool = False


def _run(command: Sequence[str], *, env: dict[str, str] | None = None) -> int:
    print(f"\n[local-github-checks] $ {' '.join(command)}", flush=True)
    try:
        completed = subprocess.run(command, cwd=ROOT, env=env, check=False)  # noqa: S603
    except FileNotFoundError:
        print(f"[local-github-checks] missing executable: {command[0]}", file=sys.stderr)
        return 127
    return completed.returncode


def _pythonpath_env() -> dict[str, str]:
    env = os.environ.copy()
    src = str(ROOT / "src")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = src if not existing else os.pathsep.join([src, existing])
    return env


def _bash() -> str:
    git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
    if platform.system() == "Windows" and git_bash.exists():
        return str(git_bash)
    found = shutil.which("bash")
    if found:
        return found
    return "bash"


def _dist_paths() -> list[str]:
    paths = sorted(
        str(path.relative_to(ROOT))
        for pattern in ("*.whl", "*.tar.gz")
        for path in (ROOT / "dist").glob(pattern)
    )
    return paths or ["dist/*"]


def _cmd(name: str) -> str:
    if platform.system() == "Windows":
        found = shutil.which(f"{name}.cmd")
        if found:
            return found
    return name


def _package_version() -> str:
    with (ROOT / "package.json").open(encoding="utf-8") as fh:
        return str(json.load(fh)["version"])


def _assert_npm_wrapper_pins_version() -> int:
    cli = ROOT / "bin" / "cli.js"
    text = cli.read_text(encoding="utf-8")
    failed = False
    if "@latest" in text:
        print("bin/cli.js still uses @latest", file=sys.stderr)
        failed = True
    if "ai-repo-safety==${version}" not in text:
        print("bin/cli.js does not pin ai-repo-safety to package.json version", file=sys.stderr)
        failed = True
    return 1 if failed else 0


def _assert_package_version(expected_version: str) -> int:
    actual = _package_version()
    if actual != expected_version:
        print(f"package.json version {actual!r} != expected tag version {expected_version!r}", file=sys.stderr)
        return 1
    return 0


def _opengrep_check() -> int:
    if not shutil.which("opengrep"):
        print("[local-github-checks] SKIP opengrep: tool is not installed; GitHub workflow is a placeholder")
        return 0
    rules = ROOT / "src" / "ai_repo_safety" / "assets" / "rules" / "opengrep"
    return _run(["opengrep", "--config", str(rules), "--exclude", "src/ai_repo_safety/assets/rules/opengrep", "."])


def _github_only_notes() -> list[Check]:
    return [
        Check(
            "dependency-review",
            note=(
                "GitHub-only: actions/dependency-review-action needs pull_request dependency diff context. "
                "Local coverage is pip-audit plus OSV-Scanner below."
            ),
        ),
        Check(
            "codeql-optional",
            note=(
                "GitHub-only in this repo: github/codeql-action writes SARIF to GitHub code scanning. "
                "Local SAST coverage is Bandit, Ruff, and Opengrep below."
            ),
        ),
        Check(
            "scorecard",
            note=(
                "GitHub-only: ossf/scorecard-action publishes SARIF with id-token/security-events permissions. "
                "Local release hygiene coverage is verify-release below."
            ),
        ),
    ]


def _checks(expected_version: str) -> list[Check]:
    return [
        Check("ci / test py3.12", ["uv", "run", "--extra", "dev", "--python", "3.12", "pytest", "-q"]),
        Check("ci / test py3.13", ["uv", "run", "--extra", "dev", "--python", "3.13", "pytest", "-q"]),
        Check("ci+sast / ruff", ["uvx", "ruff", "check", "."]),
        Check("sast / bandit", ["uvx", "bandit", "-q", "-r", "src", "-x", "tests,.venv,venv"]),
        Check("sast / pip-audit", ["uvx", "--with", "msgpack>=1.2.1", "pip-audit"]),
        Check("sast / opengrep placeholder local equivalent"),
        Check("ci / uv build", ["uv", "build"]),
        Check("publish-pypi / uv build --no-sources", ["uv", "build", "--no-sources"]),
        Check("ci+publish-pypi / twine check"),
        Check("ci / artifact manifest", [sys.executable, "scripts/check-package-artifacts.py"]),
        Check("ci+publish-pypi / installed wheel smoke", [_bash(), "scripts/smoke-wheel.sh"]),
        Check("ci+publish-npm / npm pack", [_cmd("npm"), "pack", "--dry-run"]),
        Check("ci / npm wrapper pin"),
        Check("publish-npm / package version matches tag"),
        Check("security / gitleaks", ["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"]),
        Check(
            "security / trufflehog",
            ["trufflehog", "git", "file://.", "--no-update", "--results=verified,unknown", "--fail"],
        ),
        Check("supply-chain / osv", ["osv-scanner", "scan", "source", "-r", "--allow-no-lockfiles", "."]),
        Check("supply-chain / pip-audit", ["uvx", "--with", "msgpack>=1.2.1", "pip-audit"]),
        Check(
            "local repo-safety precommit gate",
            [sys.executable, "-m", "ai_repo_safety", "scan", "--target", ".", "--offline"],
        ),
        Check("release hygiene / verify-release", [sys.executable, "-m", "ai_repo_safety", "verify-release", "--version", expected_version]),
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--version",
        default=None,
        help="expected release/tag version for publish workflow parity; defaults to package.json version",
    )
    args = parser.parse_args(argv)
    expected_version = args.version or _package_version()

    failures: list[str] = []
    for check in _github_only_notes():
        print(f"[local-github-checks] NOTE {check.name}: {check.note}")

    for check in _checks(expected_version):
        if check.name == "sast / opengrep placeholder local equivalent":
            code = _opengrep_check()
        elif check.name == "ci+publish-pypi / twine check":
            code = _run(["uvx", "twine", "check", *_dist_paths()])
        elif check.name == "ci / npm wrapper pin":
            print("\n[local-github-checks] npm wrapper pin", flush=True)
            code = _assert_npm_wrapper_pins_version()
        elif check.name == "publish-npm / package version matches tag":
            print("\n[local-github-checks] package version matches tag", flush=True)
            code = _assert_package_version(expected_version)
        else:
            assert check.command is not None
            env = _pythonpath_env() if "ai_repo_safety" in check.command else None
            code = _run(check.command, env=env)
        if code != 0:
            failures.append(check.name)

    if failures:
        print("\n[local-github-checks] FAIL")
        for name in failures:
            print(f"  - {name}")
        return 1
    print("\n[local-github-checks] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
