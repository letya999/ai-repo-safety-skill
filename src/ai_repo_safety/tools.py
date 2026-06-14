from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from pathlib import Path

from .util import current_platform, run_cmd, which


@dataclass
class ToolSpec:
    name: str
    command: str
    required: bool
    purpose: str
    install_hint: str
    version_args: tuple[str, ...] = ("--version",)


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec("Git", "git", True, "source control and hooks", "Install Git from official docs or OS package manager."),
    ToolSpec("Python", "python", True, "runtime; Python 3.12+ required", "Install Python 3.12+ or use `uv python install 3.12`."),
    ToolSpec("uv", "uv", True, "Python package/project manager", "Install uv from Astral official docs."),
    ToolSpec("uvx", "uvx", True, "run Python tools in isolated envs", "uvx is installed with uv; update/reinstall uv if missing."),
    ToolSpec("pre-commit", "pre-commit", False, "local commit hooks", "Install with `uv tool install pre-commit`."),
    ToolSpec("Gitleaks", "gitleaks", False, "fast secret scanning", "Install from Gitleaks official releases or package manager."),
    ToolSpec("TruffleHog", "trufflehog", False, "deep secret scanning and verification", "Install from TruffleHog official docs/releases."),
    ToolSpec("detect-secrets", "detect-secrets", False, "baseline-oriented secret scanner", "Install with `uv tool install detect-secrets`."),
    ToolSpec("Opengrep", "opengrep", False, "open-source SAST pattern engine", "Install from Opengrep official docs/releases; use current stable compatible version."),
    ToolSpec("Bandit", "bandit", False, "Python SAST", "Install with `uv tool install bandit`."),
    ToolSpec("Ruff", "ruff", False, "Python lint/security rules", "Install with `uv tool install ruff`."),
    ToolSpec("pip-audit", "pip-audit", False, "Python dependency vulnerability scanner", "Install with `uv tool install pip-audit`."),
    ToolSpec("OSV-Scanner", "osv-scanner", False, "open-source vulnerability scanner", "Install from OSV-Scanner official releases or package manager."),
    ToolSpec("GitHub CLI", "gh", False, "GitHub read guard backend", "Install GitHub CLI from official docs or package manager."),
    ToolSpec("git-filter-repo", "git-filter-repo", False, "clean leaked secrets from Git history", "Install with `uv tool install git-filter-repo` or OS package manager."),
]

PYTHON_TOOL_COMMANDS = {
    "pre-commit": "uv tool install pre-commit",
    "detect-secrets": "uv tool install detect-secrets",
    "bandit": "uv tool install bandit",
    "ruff": "uv tool install ruff",
    "pip-audit": "uv tool install pip-audit",
    "git-filter-repo": "uv tool install git-filter-repo",
}


def check_python_312() -> tuple[bool, str]:
    version = sys.version_info
    ok = version >= (3, 12)
    return ok, f"{version.major}.{version.minor}.{version.micro}"


def check_tool(spec: ToolSpec) -> tuple[bool, str]:
    path = which(spec.command)
    if not path:
        return False, "missing"
    code, out, err = run_cmd([spec.command, *spec.version_args], timeout=20)
    version = (out or err or path).strip().splitlines()[0] if (out or err) else path
    if len(version) > 100:
        version = version[:100] + "..."
    return True, version


def doctor(*, agent_plan: bool = False) -> int:
    print(f"AI Repo Safety Doctor")
    print(f"Platform: {current_platform()}")
    print(f"Python executable: {sys.executable}")
    print()

    rows: list[tuple[str, str, str]] = [("Tool", "Status", "Details")]
    missing_required: list[ToolSpec] = []
    missing_optional: list[ToolSpec] = []

    py_ok, py_ver = check_python_312()
    if not py_ok:
        rows.append(("Python version", "FAIL", f"{py_ver}; Python 3.12+ required"))
    else:
        rows.append(("Python version", "OK", py_ver))

    for spec in TOOL_SPECS:
        ok, details = check_tool(spec)
        status = "OK" if ok else ("FAIL" if spec.required else "MISSING")
        rows.append((spec.name, status, details if ok else spec.install_hint))
        if not ok and spec.required:
            missing_required.append(spec)
        elif not ok:
            missing_optional.append(spec)

    from .util import print_table
    print_table(rows)
    print()

    if missing_required or agent_plan:
        print("Agent install plan:")
        print("1. For every missing tool, search the official documentation or official releases for the current stable compatible version.")
        print("2. Prefer uv/uvx for Python tools and official OS package managers for system binaries.")
        print("3. Do not install random blog snippets, curl|bash commands from untrusted pages, or unpinned binaries.")
        print("4. Re-run `ai-repo-safety doctor` after installation.")
        print()
        for spec in missing_required + missing_optional:
            py_cmd = PYTHON_TOOL_COMMANDS.get(spec.command)
            if py_cmd:
                print(f"- {spec.name}: try `{py_cmd}`; if it fails, search official docs for stable compatible install.")
            else:
                print(f"- {spec.name}: {spec.install_hint}")

    if not py_ok or missing_required:
        return 2
    return 0



def install_missing_python_tools(*, dry_run: bool = False) -> int:
    """Install only Python-based helper tools through uv tool install.

    System binaries are intentionally not auto-installed because their trusted
    installation method differs across Windows/macOS/Linux. For those, the
    agent must search official docs/releases and choose the stable compatible
    install method.
    """
    if not which("uv"):
        print("[repo-safety] uv is missing; cannot install Python tools. Run doctor and install uv first.")
        return 2
    failures = 0
    for command, install_cmd in PYTHON_TOOL_COMMANDS.items():
        if which(command):
            print(f"[repo-safety] {command} already installed")
            continue
        args = install_cmd.split()
        print(f"[repo-safety] {'would run' if dry_run else 'running'}: {install_cmd}")
        if not dry_run:
            code, out, err = run_cmd(args, timeout=600)
            if out:
                print(out.rstrip())
            if err:
                print(err.rstrip())
            if code != 0:
                failures += 1
                print(f"[repo-safety] failed to install {command}")
    print("[repo-safety] system tools still require agent-managed official install if missing: gitleaks, trufflehog, opengrep, osv-scanner, gh")
    return 1 if failures else 0
