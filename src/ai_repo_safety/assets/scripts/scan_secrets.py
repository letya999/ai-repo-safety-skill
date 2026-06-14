from __future__ import annotations

import shutil
import subprocess

COMMANDS = [
    ["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"],
    ["trufflehog", "git", "file://.", "--results=verified,unknown", "--fail"],
]


def main() -> int:
    failed = 0
    for cmd in COMMANDS:
        if not shutil.which(cmd[0]):
            print(f"[repo-safety] missing {cmd[0]}, skipping")
            continue
        print(f"[repo-safety] running: {' '.join(cmd)}")
        failed += subprocess.run(cmd).returncode != 0
    return 1 if failed else 0

if __name__ == "__main__":
    raise SystemExit(main())
