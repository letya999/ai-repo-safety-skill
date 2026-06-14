from __future__ import annotations

import shutil
import subprocess
import sys


def run(command: list[str], required: bool = False) -> int:
    if not shutil.which(command[0]):
        print(f"[repo-safety] {'ERROR' if required else 'WARN'}: missing {command[0]}")
        return 2 if required else 0
    print(f"[repo-safety] running: {' '.join(command)}")
    proc = subprocess.run(command)
    return proc.returncode


def main() -> int:
    failures = 0
    checks = [
        (["python", "scripts/security/forbid_sensitive_files.py", "--all"], True),
        (["python", "scripts/security/scan_mcp_config.py"], True),
        (["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"], False),
        (["trufflehog", "git", "file://.", "--since-commit", "HEAD~20", "--results=verified,unknown", "--fail"], False),
    ]
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
