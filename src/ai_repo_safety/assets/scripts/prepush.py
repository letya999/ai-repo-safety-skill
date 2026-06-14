from __future__ import annotations

import shutil
import subprocess  # nosec


def run(command: list[str], required: bool = False) -> int:
    if not shutil.which(command[0]):
        print(f"[repo-safety] {'ERROR' if required else 'WARN'}: missing {command[0]}")
        return 2 if required else 0
    print(f"[repo-safety] running: {' '.join(command)}")
    proc = subprocess.run(command)  # nosec
    return proc.returncode


def git_has_commits() -> bool:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True)  # nosec
    return proc.returncode == 0


def main() -> int:
    failures = 0
    checks = [
        (["python", "scripts/security/forbid_sensitive_files.py", "--all"], True),
        (["python", "scripts/security/scan_mcp_config.py"], True),
        (["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"], False),
    ]
    if git_has_commits():
        checks.append((["trufflehog", "git", "file://.", "--since-commit", "HEAD~20", "--results=verified,unknown", "--fail"], False))
    else:
        checks.append((["trufflehog", "filesystem", ".", "--results=verified,unknown", "--fail"], False))

    for command, required in checks:
        code = run(command, required=required)
        if code not in (0, 2):
            failures += 1
        if code == 2 and required:
            failures += 1
    if failures:
        print("[repo-safety] push blocked")
        return 1
    print("[repo-safety] pre-push passed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
