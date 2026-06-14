from __future__ import annotations

from pathlib import Path

from .util import detect_python_project, project_root, run_cmd, which, git_has_commits


def run_available(command: list[str], *, cwd: Path, required: bool = False, timeout: int = 300) -> int:
    if not which(command[0]):
        level = "ERROR" if required else "WARN"
        print(f"[repo-safety] {level}: missing tool `{command[0]}`; run `ai-repo-safety doctor --agent-plan`")
        return 2 if required else 0
    print(f"[repo-safety] running: {' '.join(command)}")
    code, out, err = run_cmd(command, cwd=cwd, timeout=timeout)
    if out:
        print(out.rstrip())
    if err:
        print(err.rstrip())
    if code != 0:
        print(f"[repo-safety] command failed: {' '.join(command)}")
    return code


def scan(target: str | Path, *, strict: bool = False) -> int:
    root = project_root(target)
    failures = 0

    local_scripts = [
        ["python", "scripts/security/forbid_sensitive_files.py", "--all"],
        ["python", "scripts/security/scan_mcp_config.py"],
    ]
    for command in local_scripts:
        if (root / command[1]).exists():
            failures += 1 if run_available(command, cwd=root, required=True) != 0 else 0

    commands = [
        ["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"],
    ]
    if git_has_commits(root):
        commands.append(["trufflehog", "git", "file://.", "--results=verified,unknown", "--fail"])
    else:
        commands.append(["trufflehog", "filesystem", ".", "--results=verified,unknown", "--fail"])

    for command in commands:
        code = run_available(command, cwd=root, required=strict)
        if code != 0 and code != 2:
            failures += 1
        elif strict and code == 2:
            failures += 1

    opengrep_rules = root / ".repo-safety" / "opengrep"
    if opengrep_rules.exists():
        command = ["opengrep", "--config", str(opengrep_rules), "."]
        code = run_available(command, cwd=root, required=False)
        if code not in (0, 2):
            failures += 1

    if detect_python_project(root):
        for command in [
            ["bandit", "-q", "-r", "src", "-x", "tests"],
            ["ruff", "check", "."],
            ["pip-audit"],
        ]:
            code = run_available(command, cwd=root, required=False)
            if code not in (0, 2):
                failures += 1

    if failures:
        print(f"[repo-safety] scan failed with {failures} failing check(s)")
        return 1
    print("[repo-safety] scan completed")
    return 0


def prepush(target: str | Path) -> int:
    root = project_root(target)
    failures = 0
    commands = [
        ["python", "scripts/security/forbid_sensitive_files.py", "--all"],
        ["python", "scripts/security/scan_mcp_config.py"],
        ["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"],
    ]
    if git_has_commits(root):
        commands.append(["trufflehog", "git", "file://.", "--since-commit", "HEAD~20", "--results=verified,unknown", "--fail"])
    else:
        commands.append(["trufflehog", "filesystem", ".", "--results=verified,unknown", "--fail"])

    for command in commands:
        if command[0] == "python" and not (root / command[1]).exists():
            continue
        code = run_available(command, cwd=root, required=command[0] == "python")
        if code not in (0, 2):
            failures += 1
        elif code == 2 and command[0] == "python":
            failures += 1
    if failures:
        print("[repo-safety] push blocked")
        return 1
    print("[repo-safety] pre-push passed")
    return 0
