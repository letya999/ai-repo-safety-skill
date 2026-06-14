from __future__ import annotations

import re
from pathlib import Path

RISKY_NAMES = [".mcp.json", "claude_desktop_config.json"]
RISKY_COMMAND_PATTERNS = [
    re.compile(r"curl\s+.*\|\s*(bash|sh)", re.I),
    re.compile(r"wget\s+.*\|\s*(bash|sh)", re.I),
    re.compile(r"powershell.*(iex|invoke-expression)", re.I),
    re.compile(r"python\s+-c\s+", re.I),
    re.compile(r"node\s+-e\s+", re.I),
]
SECRET_LIKE = re.compile(r"(?i)(token|secret|password|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/.=]{12,}")


def main() -> int:
    problems = []
    for name in RISKY_NAMES:
        path = Path(name)
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if SECRET_LIKE.search(text):
            problems.append(f"{name}: contains secret-like plaintext")
        for pat in RISKY_COMMAND_PATTERNS:
            if pat.search(text):
                problems.append(f"{name}: risky command pattern `{pat.pattern}`")
    if problems:
        print("[repo-safety] MCP config risks:")
        for p in problems:
            print(f"  - {p}")
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
