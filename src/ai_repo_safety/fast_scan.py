from __future__ import annotations

import os
import re
import fnmatch
from pathlib import Path

# Common directories to ignore during the scan
IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".git-rewrite",
    "build",
    "dist",
}

# File name patterns that are forbidden (forbidden files)
FORBIDDEN_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa",
    "id_ed25519",
    "credentials*.json",
    "service-account*.json",
    "token.json",
    "tokens.json",
    "secrets.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "*.ovpn",
]

# High-confidence patterns for secrets within files
SECRET_PATTERNS = [
    (re.compile(r"ghp_[A-Za-z0-9_]{36,255}"), "GitHub Personal Access Token (classic)"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{82}"), "GitHub Fine-Grained Personal Access Token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "Private Key Header"),
    (re.compile(r"(?i)\b(?:aws_)?secret(?:_access)?_key\s*=\s*['\"]([A-Za-z0-9/+=]{40})['\"]"), "Potential AWS Secret Access Key"),
    (re.compile(r"(?i)\b(?:slack_)?token\s*=\s*['\"](xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+)['\"]"), "Potential Slack Bot Token"),
]

def is_ignored_directory(path: Path, root: Path) -> bool:
    """Check if the directory or any of its parent directories up to the root should be ignored."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    for part in relative.parts:
        if part in IGNORED_DIRS:
            return True
    return False

def scan_directory(target_dir: str | Path) -> list[dict]:
    root = Path(target_dir).resolve()
    findings = []

    # 1. Walk directory and check filenames
    for dirpath, dirnames, filenames in os.walk(root):
        # Filter out ignored directories in-place to prevent os.walk from entering them
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        
        current_dir = Path(dirpath)
        if is_ignored_directory(current_dir, root):
            continue

        for filename in filenames:
            file_path = current_dir / filename
            rel_path = file_path.relative_to(root)
            rel_path_str = str(rel_path).replace("\\", "/")

            # Check if filename matches any forbidden pattern
            is_forbidden = False
            for pattern in FORBIDDEN_PATTERNS:
                if fnmatch.fnmatch(filename, pattern):
                    findings.append({
                        "file": rel_path_str,
                        "type": "forbidden_file",
                        "message": f"Forbidden file found: {filename} (matched pattern: {pattern})"
                    })
                    is_forbidden = True
                    break
            
            # If it's a forbidden file, no need to scan its contents for secrets again
            if is_forbidden:
                continue

            # Check inside files (only smaller text files)
            try:
                # Ignore files larger than 1MB to keep scan super fast
                if file_path.stat().st_size > 1024 * 1024:
                    continue

                # Read and check for secrets line by line to get line numbers
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern, desc in SECRET_PATTERNS:
                            match = pattern.search(line)
                            if match:
                                findings.append({
                                    "file": rel_path_str,
                                    "line": line_num,
                                    "type": "secret_content",
                                    "message": f"Potential {desc} detected"
                                })
            except (OSError, UnicodeDecodeError):
                # Ignore unreadable or binary files
                continue

    return findings
