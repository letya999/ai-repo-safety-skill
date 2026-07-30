from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Mapping

from .util import project_root, run_cmd, which, git_has_commits


def run_available(
    command: list[str],
    *,
    cwd: Path,
    required: bool = False,
    timeout: int = 300,
    env: Mapping[str, str] | None = None,
) -> tuple[int, str, str]:
    if not which(command[0]):
        level = "ERROR" if required else "WARN"
        print(
            f"[repo-safety] {level}: missing tool `{command[0]}`; run `ai-repo-safety doctor --agent-plan`"
        )
        return 127, "", f"missing:{command[0]}"
    print(f"[repo-safety] running: {' '.join(command)}")
    code, out, err = run_cmd(command, cwd=cwd, timeout=timeout, env=env)
    if out:
        print(out.rstrip())
    if err:
        print(err.rstrip())
    if code != 0:
        print(f"[repo-safety] command failed: {' '.join(command)}")
    return code, out, err


def run_optional_tool(
    tool: str,
    command: list[str],
    *,
    cwd: Path,
    timeout: int = 300,
) -> tuple[int, str, str]:
    if not which(tool):
        print(
            f"[repo-safety] WARN: missing tool `{tool}`; run `ai-repo-safety doctor --agent-plan`"
        )
        return 127, "", f"missing:{tool}"
    return run_available(command, cwd=cwd, required=False, timeout=timeout)


def _python_executable() -> list[str]:
    """Return the python executable to invoke for the local security
    helper scripts that ship under .repo-safety/scripts/. We use
    sys.executable so the same Python that runs the CLI runs the
    helpers; on systems where `python` is missing, the helpers
    still work as long as the user is in the venv that installed
    ai-repo-safety."""
    return [sys.executable]


def _helper_script(root: Path, name: str) -> str | None:
    for rel in (f".repo-safety/scripts/{name}", f"scripts/security/{name}"):
        if (root / rel).exists():
            return rel
    return None


def _resolve_trufflehog_since_commit(root: Path) -> str | None:
    """Pick a safe 'since' revision for TruffleHog.

    Returns None if no commit on the local branch can be used as a
    stable lower bound. TruffleHog accepts a commit SHA, and a
    missing or invalid SHA makes the tool error out.
    """
    candidates: list[list[str]] = [
        ["git", "merge-base", "HEAD", "@{upstream}"],
        ["git", "merge-base", "HEAD", "origin/main"],
        ["git", "merge-base", "HEAD", "origin/dev"],
    ]
    for cmd in candidates:
        code, out, _ = run_cmd(cmd, cwd=root, timeout=20)
        if code == 0 and out.strip():
            return out.strip()
    code, out, _ = run_cmd(
        ["git", "rev-list", "--max-count=20", "HEAD"], cwd=root, timeout=20
    )
    if code == 0:
        commits = [line.strip() for line in out.splitlines() if line.strip()]
        if len(commits) >= 2:
            return commits[-1]
    return None


def _trufflehog_exclude_args(root: Path) -> list[str]:
    exclude_file = root / ".repo-safety" / "trufflehog-exclude.txt"
    if exclude_file.exists():
        return ["--exclude-paths", str(exclude_file)]
    fh = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    with fh:
        fh.write(r"(^|[\\/])(\.venv|venv|node_modules|\.opencode[\\/]node_modules|\.agents[\\/]node_modules)([\\/]|$)" + "\n")
    return ["--exclude-paths", fh.name]


def _pip_audit_env(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    candidates = [
        root / ".venv" / "Scripts" / "python.exe",
        root / ".venv" / "bin" / "python",
    ]
    for candidate in candidates:
        if candidate.exists():
            env["PIPAPI_PYTHON_LOCATION"] = str(candidate)
            return env
    env["PIPAPI_PYTHON_LOCATION"] = sys.executable
    return env


def _looks_like_go_repo(root: Path) -> bool:
    return (root / "go.mod").exists()


def _looks_like_rust_repo(root: Path) -> bool:
    return (root / "Cargo.toml").exists()


def _looks_like_js_repo(root: Path) -> bool:
    return any((root / name).exists() for name in ("package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"))


def scan(
    target: str | Path,
    *,
    strict: bool = False,
    offline: bool = False,
    agent_skills: bool = False,
    allow_cloud_agent_scan: bool = False,
) -> int:
    root = project_root(target)
    failures = 0
    network_required_skipped: list[str] = []

    py = _python_executable()
    for name, args in [
        ("forbid_sensitive_files.py", ["--all"]),
        ("scan_mcp_config.py", []),
    ]:
        script = _helper_script(root, name)
        if script:
            command = py + [script, *args]
            failures += (
                1 if run_available(command, cwd=root, required=True)[0] != 0 else 0
            )

    commands: list[list[str]] = [
        ["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"],
    ]
    if git_has_commits(root):
        since = _resolve_trufflehog_since_commit(root) if not offline else None
        if since:
            commands.append(
                [
                    "trufflehog",
                    "git",
                    "file://.",
                    "--no-update",
                    "--since-commit",
                    since,
                    *_trufflehog_exclude_args(root),
                    "--results=verified,unknown",
                    "--fail",
                ]
            )
        else:
            commands.append(
                [
                    "trufflehog",
                    "filesystem",
                    ".",
                    "--no-update",
                    *_trufflehog_exclude_args(root),
                    "--results=verified,unknown",
                    "--fail",
                ]
            )
    else:
        commands.append(
            [
                "trufflehog",
                "filesystem",
                ".",
                "--no-update",
                *_trufflehog_exclude_args(root),
                "--results=verified,unknown",
                "--fail",
            ]
        )

    for command in commands:
        code, _, _ = run_available(command, cwd=root, required=strict)
        if code != 0 and code != 127:
            failures += 1
        elif strict and code == 127:
            failures += 1

    opengrep_rules = root / ".repo-safety" / "opengrep"
    if opengrep_rules.exists():
        command = [
            "opengrep",
            "--config",
            str(opengrep_rules),
            "--exclude",
            ".repo-safety/opengrep/",
            "--exclude",
            "src/ai_repo_safety/assets/rules/opengrep/",
            ".",
        ]
        code, _, _ = run_available(command, cwd=root, required=False)
        if code not in (0, 127):
            failures += 1

    if (
        (root / "pyproject.toml").exists()
        or (root / "requirements.txt").exists()
        or any(root.glob("**/*.py"))
    ):
        for command in [
            ["bandit", "-q", "-r", "src", "-x", "tests"],
            ["ruff", "check", "."],
        ]:
            code, _, _ = run_available(command, cwd=root, required=False)
            if code not in (0, 127):
                failures += 1

        if offline:
            print("[repo-safety] skipping pip-audit (offline mode): network_required")
            network_required_skipped.append("pip-audit")
        else:
            command = ["pip-audit"]
            code, _, _ = run_available(
                command, cwd=root, required=False, env=_pip_audit_env(root)
            )
            if code not in (0, 127):
                if code == 127:
                    network_required_skipped.append("pip-audit")
                else:
                    failures += 1

    if _looks_like_go_repo(root):
        go_commands = [["gosec", "./..."]]
        if offline:
            print("[repo-safety] skipping govulncheck (offline mode): network_required")
        else:
            go_commands.append(["govulncheck", "./..."])
        for command in go_commands:
            code, _, _ = run_available(command, cwd=root, required=False)
            if code not in (0, 127):
                failures += 1

    if _looks_like_rust_repo(root):
        for tool, command in [
            ("cargo-audit", ["cargo", "audit"]),
            ("cargo-deny", ["cargo", "deny", "check"]),
        ]:
            code, _, _ = run_optional_tool(tool, command, cwd=root)
            if code not in (0, 127):
                failures += 1

    if _looks_like_js_repo(root):
        js_commands = [["eslint", "."]]
        if offline:
            print("[repo-safety] skipping npm audit (offline mode): network_required")
        else:
            js_commands.append(["npm", "audit", "--audit-level=moderate"])
        for command in js_commands:
            code, _, _ = run_available(command, cwd=root, required=False)
            if code not in (0, 127):
                failures += 1

    if agent_skills:
        for command in [["skillspector", "scan", ".", "--no-llm"], ["skill-scanner", "scan", "."]]:
            code, _, _ = run_available(command, cwd=root, required=False)
            if code not in (0, 127):
                failures += 1
        if allow_cloud_agent_scan:
            code, _, _ = run_available(["snyk-agent-scan", "scan"], cwd=root, required=False)
            if code not in (0, 127):
                failures += 1
        elif which("snyk-agent-scan"):
            print("[repo-safety] skipping snyk-agent-scan: pass --allow-cloud-agent-scan to allow cloud-backed metadata analysis")

    if failures:
        print(f"[repo-safety] scan failed with {failures} failing check(s)")
        return 1
    if network_required_skipped and strict:
        print(
            f"[repo-safety] scan partial: skipped {network_required_skipped} under --strict"
        )
        return 3
    print("[repo-safety] scan completed")
    return 0


def prepush(target: str | Path, *, offline: bool = False) -> int:
    root = project_root(target)
    failures = 0
    py = _python_executable()
    commands: list[list[str]] = []
    for name, args in [
        ("forbid_sensitive_files.py", ["--all"]),
        ("scan_mcp_config.py", []),
    ]:
        script = _helper_script(root, name)
        if script:
            commands.append(py + [script, *args])
    commands.append(["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"])
    if git_has_commits(root):
        since = _resolve_trufflehog_since_commit(root)
        if since:
            commands.append(
                [
                    "trufflehog",
                    "git",
                    "file://.",
                    "--no-update",
                    "--since-commit",
                    since,
                    *_trufflehog_exclude_args(root),
                    "--results=verified,unknown",
                    "--fail",
                ]
            )
        else:
            commands.append(
                [
                    "trufflehog",
                    "filesystem",
                    ".",
                    "--no-update",
                    *_trufflehog_exclude_args(root),
                    "--results=verified,unknown",
                    "--fail",
                ]
            )
    else:
        commands.append(
            [
                "trufflehog",
                "filesystem",
                ".",
                "--no-update",
                *_trufflehog_exclude_args(root),
                "--results=verified,unknown",
                "--fail",
            ]
        )

    for command in commands:
        if command[0] == sys.executable and not (root / command[1]).exists():
            continue
        required = command[0] == sys.executable
        code, _, _ = run_available(command, cwd=root, required=required)
        if code not in (0, 127):
            failures += 1
        elif code == 127 and required:
            failures += 1
    if failures:
        print("[repo-safety] push blocked")
        return 1
    print("[repo-safety] pre-push passed")
    return 0
