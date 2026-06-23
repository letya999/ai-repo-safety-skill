from __future__ import annotations

import argparse
import json
import re
import subprocess  # nosec
import sys
from datetime import UTC, datetime
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


def extract_payload(stdin_text: str) -> dict:
    if not stdin_text.strip():
        return {}
    try:
        payload = json.loads(stdin_text)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def is_sensitive_command(command: str) -> bool:
    return bool(command and SENSITIVE_COMMAND_RE.search(command))


def load_repo_policy(root: Path) -> dict:
    path = root / ".repo-safety.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _mcp_policy(root: Path) -> dict:
    policy = load_repo_policy(root).get("mcp_policy", {})
    if isinstance(policy, dict):
        return policy
    return {}


def is_repo_mcp_tool(tool_name: str) -> bool:
    return tool_name.startswith("mcp__github__") or tool_name.startswith("mcp__gitlab__")


def is_write_capable_mcp_tool(tool_name: str) -> bool:
    if not is_repo_mcp_tool(tool_name):
        return False

    _, _, action = tool_name.partition("__")
    _, _, action = action.partition("__")
    tokens = [token for token in re.split(r"[^a-z0-9]+", action.lower()) if token]
    if not tokens:
        return False

    leading_write = {
        "approve",
        "cancel",
        "close",
        "create",
        "comment",
        "delete",
        "edit",
        "execute",
        "merge",
        "note",
        "publish",
        "push",
        "reopen",
        "retry",
        "rerun",
        "run",
        "set",
        "trigger",
        "unassign",
        "update",
        "upload",
        "write",
        "assign",
    }
    leading_read = {
        "get",
        "list",
        "read",
        "search",
        "find",
        "view",
        "show",
        "fetch",
        "describe",
        "diff",
        "status",
    }

    if tokens[0] in leading_read:
        return False
    return tokens[0] in leading_write


def mcp_tool_allowed(root: Path, tool_name: str) -> bool:
    allowlist = _mcp_policy(root).get("allow_write_tools", [])
    if not isinstance(allowlist, list):
        return False
    return any(isinstance(item, str) and re.fullmatch(item, tool_name) for item in allowlist)


def mcp_audit_log_path(root: Path) -> Path:
    value = _mcp_policy(root).get("audit_log")
    if isinstance(value, str) and value.strip():
        return root / value
    return root / ".repo-safety" / "logs" / "mcp-audit.jsonl"


def append_mcp_audit_record(root: Path, payload: dict) -> None:
    log_path = mcp_audit_log_path(root)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "hook_event_name": payload.get("hook_event_name"),
        "tool_name": payload.get("tool_name"),
        "tool_input": payload.get("tool_input"),
        "cwd": payload.get("cwd"),
        "decision": payload.get("decision", "observe"),
    }
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


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
                "--no-update",
                "--since-commit",
                since,
                "--results=verified,unknown",
                "--fail",
            ]
    return ["trufflehog", "filesystem", ".", "--no-update", "--results=verified,unknown", "--fail"]


def gitleaks_command() -> list[str]:
    return ["gitleaks", "detect", "--source", ".", "--redact", "--exit-code", "1"]


def opengrep_command(root: Path) -> list[str] | None:
    rules_dir = root / ".repo-safety" / "opengrep"
    if not rules_dir.exists():
        return None
    return [
        "opengrep",
        "--config",
        str(rules_dir),
        "--exclude",
        "src/ai_repo_safety/assets/rules/opengrep/",
        ".",
    ]


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
        if profile == "mcp-invocation-audit":
            return 0, ""
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


def run_mcp_audit_profile(root: Path, payload: dict) -> tuple[int, str]:
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name.startswith("mcp__"):
        return 0, ""

    decision = "observe"
    if is_write_capable_mcp_tool(tool_name):
        if not mcp_tool_allowed(root, tool_name):
            decision = "deny"

    audit_payload = dict(payload)
    audit_payload["decision"] = decision
    append_mcp_audit_record(root, audit_payload)

    if decision == "deny":
        return 2, (
            "[repo-safety] blocking write-capable MCP tool call: "
            f"{tool_name}. Add an explicit allowlist entry under `.repo-safety.json` "
            "mcp_policy.allow_write_tools if this operation is intended."
        )
    return 0, ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Minimal agent hook preflight for sensitive commands.")
    parser.add_argument("--check", choices=["bandit", "trufflehog", "gitleaks", "opengrep"])
    parser.add_argument("--profile", choices=["sensitive-preflight", "mcp-invocation-audit"])
    parser.add_argument("--command")
    args = parser.parse_args(argv)
    if bool(args.check) == bool(args.profile):
        parser.error("exactly one of --check or --profile is required")

    root = Path.cwd()
    stdin_text = sys.stdin.read()
    if args.profile:
        payload = extract_payload(stdin_text)
        if args.profile == "mcp-invocation-audit":
            code, message = run_mcp_audit_profile(root, payload)
        else:
            command = extract_command(stdin_text, args.command)
            if not is_sensitive_command(command):
                return 0
            code, message = run_profile(args.profile, root)
    else:
        command = extract_command(stdin_text, args.command)
        if not is_sensitive_command(command):
            return 0
        code, message = run_check(args.check, root)
    if code != 0 and message:
        print(message, file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
