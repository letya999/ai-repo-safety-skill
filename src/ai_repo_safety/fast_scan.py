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
    ".tmp-smoke",
}

# File name patterns that are forbidden (forbidden files). Real
# credentials, keys, and agent configs. Example / template / placeholder
# files are explicitly allowlisted by ALLOWED_FORBIDDEN_FILE_MATCHES
# below to keep this tool usable against its own templates and test
# fixtures without self-false-positives.
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

# Files matching any of these are NOT reported as forbidden, even if
# they would otherwise match a FORBIDDEN_PATTERNS entry. Keep the list
# conservative: only well-known template / example filenames.
ALLOWED_FORBIDDEN_FILE_MATCHES: set[str] = {
    ".env.example",
    "env.example",
    "example.env",
    "credentials.example.json",
    "example.credentials.json",
    "service-account.example.json",
}

# Inline pragma recognized inside the scanned file. A line that carries
# `# pragma: allowlist secret` (Python) or `// pragma: allowlist
# secret` (JS/TS) tells the scanner to skip secret detection on that
# file. The same convention is used by gitleaks and detect-secrets.
ALLOWLIST_PRAGMA_RE = re.compile(
    r"#\s*pragma:\s*allowlist\s*secret|//\s*pragma:\s*allowlist\s*secret",
    re.IGNORECASE,
)

# High-confidence patterns for secrets within files. Each entry is
# (compiled_regex, human-readable label). Kept narrow on purpose; a
# high-noise regex would cause this tool to flag its own examples and
# the wider OSS ecosystem. Entropy-based checks belong in a future
# `--paranoid` mode, not the default.
SECRET_PATTERNS = [
    (re.compile(r"ghp_[A-Za-z0-9_]{36,255}"), "GitHub Personal Access Token (classic)"),
    (re.compile(r"gho_[A-Za-z0-9_]{36,255}"), "GitHub OAuth Access Token"),
    (re.compile(r"ghu_[A-Za-z0-9_]{36,255}"), "GitHub User Token"),
    (re.compile(r"ghs_[A-Za-z0-9_]{36,255}"), "GitHub Server Token"),
    (re.compile(r"ghr_[A-Za-z0-9_]{36,255}"), "GitHub Refresh Token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{82}"), "GitHub Fine-Grained Personal Access Token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS Session Access Key ID"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "Private Key Header"),
    (re.compile(r"(?i)\b(?:aws_)?secret(?:_access)?_key\s*=\s*['\"]([A-Za-z0-9/+=]{40})['\"]"), "Potential AWS Secret Access Key"),
    (re.compile(r"(?i)\b(?:slack_)?token\s*=\s*['\"](xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+)['\"]"), "Potential Slack Bot Token"),
    (re.compile(r"(?i)\bxox[abprs]-[0-9]+-[0-9]+-[A-Za-z0-9]+"), "Potential Slack Token"),
    (re.compile(r"npm_[A-Za-z0-9]{36}"), "npm Automation Token"),
    (re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"), "PyPI Upload Token"),
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


def _has_allowlist_pragma(text: str) -> bool:
    return bool(ALLOWLIST_PRAGMA_RE.search(text))


def _is_template_placeholder_path(rel_path_str: str) -> bool:
    """Classify well-known template/fixture paths so the scanner can
    report them with a distinct finding type instead of treating them
    as live secrets."""
    p = rel_path_str.lower()
    if "/templates/" in p:
        return True
    if "/tests/fixtures/" in p:
        return True
    if p.startswith("tests/") and "/fixtures/" in p:
        return True
    return False


def scan_directory(target_dir: str | Path) -> list[dict]:
    root = Path(target_dir).resolve()
    findings: list[dict] = []

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
            is_template_path = _is_template_placeholder_path(rel_path_str)

            # Check if filename matches any forbidden pattern, with allowlist
            # for known example/template files.
            matched_forbidden: str | None = None
            for pattern in FORBIDDEN_PATTERNS:
                if fnmatch.fnmatch(filename, pattern):
                    if filename in ALLOWED_FORBIDDEN_FILE_MATCHES or is_template_path:
                        matched_forbidden = None
                    else:
                        matched_forbidden = pattern
                    break

            if matched_forbidden is not None:
                findings.append({
                    "file": rel_path_str,
                    "type": "forbidden_file",
                    "message": f"Forbidden file found: {filename} (matched pattern: {matched_forbidden})",
                })
                # If it's a real forbidden file, do not scan its contents
                # for secrets again; the filename match is the warning.
                continue

            # Check inside files (only smaller text files)
            try:
                # Ignore files larger than 1MB to keep scan super fast
                if file_path.stat().st_size > 1024 * 1024:
                    continue

                # Read and check for secrets line by line to get line numbers.
                file_text = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            if _has_allowlist_pragma(file_text):
                # The file author has explicitly opted this file out of
                # secret scanning. Honor the pragma.
                continue

            for line_num, line in enumerate(file_text.splitlines(), 1):
                for pattern, desc in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if not match:
                        continue
                    finding_type = (
                        "secret_placeholder" if is_template_path else "secret_content"
                    )
                    findings.append({
                        "file": rel_path_str,
                        "line": line_num,
                        "type": finding_type,
                        "message": f"Potential {desc} detected",
                        # Surface that the match value is intentionally
                        # suppressed in the output to avoid log echoes
                        # of real credentials when this scan is shared.
                        "redacted": True,
                    })

    return findings
