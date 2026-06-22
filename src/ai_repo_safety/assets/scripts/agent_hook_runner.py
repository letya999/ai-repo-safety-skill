from __future__ import annotations

import argparse
import json
import re
import subprocess  # nosec
import sys
from pathlib import Path

SENSITIVE_COMMAND_RE = re.compile(
    r"(^|\s)("
    r"git\s+(commit|push|tag)"
    r"|gh\s+(pr|release)\s+create"
    r"|glab\s+mr\s+create"
    r"|npm\s+publish"
    r"|pnpm\s+publish"
    r"|yarn\s+npm\s+publish"
    r"|uv\s+publish"
    r"|twine\s+upload"
    r"|poetry\s+publish"
    r")\b",
    flags=re.IGNORECASE,
)


def run_cmd(args: list[str], cwd: Path, timeout: int = 300) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(  # nosec
            args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, stdout, stderr or f"Timeout after {timeout}s"


def git_has_commits(root: Path) -> bool:
    code, _, _ = run_cmd(["git", "rev-parse", "HEAD"], cwd=root, timeout=20)
    return code == 0


def resolve_trufflehog_since_commit(root: Path) -> str | None:
    candidates = [
        ["git", "merge-base", "HEAD", "@{upstream}"],
        ["git", "merge-base", "HEAD", "origin/main"],
        ["git", "merge-base", "HEAD", "origin/dev"],
    ]
    for cmd in candidates:
        code, out, _ = run_cmd(cmd, cwd=root, timeout=20)
        if code == 0 and out.strip():
            return out.strip()
    code, out, _ = run_cmd(["git", "rev-list", "--max-count=20", "HEAD"], cwd=root, timeout=20)
    if code == 0:
        commits = [line.strip() for line in out.splitlines() if line.strip()]
        if len(commits) >= 2:
            return commits[-1]
    return None


def extract_command(stdin_text: str, explicit_command: str | None) -> str:
    if explicit_command:
        return explicit_command
    if not stdin_text.strip():
        return ""
    try:
        payload = json.loads(stdin_text)
    except json.JSONDecodeError:
        return ""
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        command = tool_input.get("command")
        if isinstance(command, str):
            return command
    return ""


def is_sensitive_command(command: str) -> bool:
    return bool(command and SENSITIVE_COMMAND_RE.search(command))


def bandit_command(root: Path) -> list[str]:
    if (root / "src").exists():
        return ["bandit", "-q", "-r", "src", "-x", "tests,.venv,venv,node_modules"]
    return ["bandit", "-q", "-r", ".", "-x", "tests,.venv,venv,node_modules"]


def trufflehog_command(root: Path) -> list[str]:
    if git_has_commits(root):
        since = resolve_trufflehog_since_commit(root)
        if since:
            return [
                "trufflehog",
                "git",
                "file://.",
                "--since-commit",
                since,
                "--results=verified,unknown",
                "--fail",
            ]
    return ["trufflehog", "filesystem", ".", "--results=verified,unknown", "--fail"]


def gitleaks_command() -> list[str]:
    return ["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"]


def opengrep_command(root: Path) -> list[str] | None:
    rules_dir = root / ".repo-safety" / "opengrep"
    if not rules_dir.exists():
        return None
    return ["opengrep", "--config", str(rules_dir), "."]


def looks_like_python_repo(root: Path) -> bool:
    return (root / "pyproject.toml").exists() or (root / "requirements.txt").exists() or (root / "src").exists()


def run_check(check: str, root: Path) -> tuple[int, str]:
    if check == "bandit":
        cmd = bandit_command(root)
    elif check == "trufflehog":
        cmd = trufflehog_command(root)
    else:
        return 2, f"unsupported check: {check}"

    code, out, err = run_cmd(cmd, cwd=root, timeout=300)
    if code == 0:
        return 0, ""
    if code == 127:
        return 2, f"[repo-safety] blocking sensitive command: required scanner `{check}` is missing"
    details = (err or out).strip()
    prefix = f"[repo-safety] blocking sensitive command: {check} failed"
    return 2, f"{prefix}\n{details}" if details else prefix


def run_profile(profile: str, root: Path) -> tuple[int, str]:
    if profile != "sensitive-preflight":
        return 2, f"unsupported profile: {profile}"

    checks: list[str] = ["gitleaks", "trufflehog"]
    if opengrep_command(root) is not None:
        checks.append("opengrep")
    if looks_like_python_repo(root):
        checks.append("bandit")

    for check in checks:
        if check == "gitleaks":
            cmd = gitleaks_command()
        elif check == "trufflehog":
            cmd = trufflehog_command(root)
        elif check == "opengrep":
            cmd = opengrep_command(root)
            if cmd is None:
                continue
        elif check == "bandit":
            cmd = bandit_command(root)
        else:
            return 2, f"unsupported check: {check}"

        code, out, err = run_cmd(cmd, cwd=root, timeout=300)
        if code == 0:
            continue
        if code == 127:
            return 2, f"[repo-safety] blocking sensitive command: required scanner `{check}` is missing"
        details = (err or out).strip()
        prefix = f"[repo-safety] blocking sensitive command: {check} failed"
        return 2, f"{prefix}\n{details}" if details else prefix

    return 0, ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Minimal agent hook preflight for sensitive commands.")
    parser.add_argument("--check", choices=["bandit", "trufflehog", "gitleaks", "opengrep"])
    parser.add_argument("--profile", choices=["sensitive-preflight"])
    parser.add_argument("--command")
    args = parser.parse_args(argv)
    if bool(args.check) == bool(args.profile):
        parser.error("exactly one of --check or --profile is required")

    root = Path.cwd()
    stdin_text = sys.stdin.read()
    command = extract_command(stdin_text, args.command)
    if not is_sensitive_command(command):
        return 0

    if args.profile:
        code, message = run_profile(args.profile, root)
    else:
        code, message = run_check(args.check, root)
    if code != 0 and message:
        print(message, file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
