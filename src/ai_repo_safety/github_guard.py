from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from .util import git_origin, load_json, parse_github_repo_from_url, project_root, run_cmd, which

SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[^'\"\s]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore (all )?(previous|prior|above) (instructions|rules)"),
    re.compile(r"(?i)system prompt"),
    re.compile(r"(?i)developer message"),
    re.compile(r"(?i)read .*\.env"),
    re.compile(r"(?i)cat .*\.env"),
    re.compile(r"(?i)printenv|env vars|environment variables"),
    re.compile(r"(?i)exfiltrate|send .*token|upload .*secret"),
    re.compile(r"(?i)curl .*(bash|sh)|wget .*(bash|sh)"),
    re.compile(r"(?i)base64 -d|powershell.*iex|Invoke-Expression"),
]

RESOURCE_ENDPOINTS = {
    "issues": "/repos/{repo}/issues?state=all&per_page={limit}",
    "pulls": "/repos/{repo}/pulls?state=all&per_page={limit}",
    "branches": "/repos/{repo}/branches?per_page={limit}",
    "commits": "/repos/{repo}/commits?per_page={limit}",
}


def load_policy(root: Path) -> dict[str, Any]:
    return load_json(root / ".repo-safety.json", default={}).get("github_read_guard", {})


def normalize_resource(policy: dict[str, Any], resource: str) -> str:
    aliases = policy.get("resource_aliases", {})
    return aliases.get(resource, resource)


def current_repo(root: Path) -> str | None:
    return parse_github_repo_from_url(git_origin(root))


def validate_request(root: Path, repo: str, resource: str, reason: str | None, limit: int | None) -> tuple[bool, str, int, str]:
    policy = load_policy(root)
    resource = normalize_resource(policy, resource)
    allowed_resources = set(policy.get("allowed_resources") or RESOURCE_ENDPOINTS.keys())
    if resource not in allowed_resources:
        return False, f"resource `{resource}` is not allowed", 0, resource

    if policy.get("require_explicit_reason", True) and not reason:
        return False, "explicit --reason is required for GitHub reads", 0, resource

    allowed_repos = set(policy.get("allowed_repositories") or [])
    origin_repo = current_repo(root)
    if not allowed_repos and origin_repo:
        allowed_repos = {origin_repo}
    if policy.get("deny_cross_repo_reads", True) and allowed_repos and repo not in allowed_repos:
        return False, f"repo `{repo}` is not in allowed repositories: {sorted(allowed_repos)}", 0, resource

    max_items = int(policy.get("max_items", 30))
    requested_limit = min(limit or max_items, max_items)
    return True, "ok", requested_limit, resource


def redact(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED_SECRET]", text)
    return text


def has_prompt_injection(text: str) -> list[str]:
    hits = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            hits.append(pattern.pattern)
    return hits


def sanitize_payload(payload: Any, *, max_body_chars: int, block_prompt_injection: bool) -> tuple[Any, list[str]]:
    warnings: list[str] = []

    def walk(value: Any, path: str = "$") -> Any:
        nonlocal warnings
        if isinstance(value, dict):
            return {k: walk(v, f"{path}.{k}") for k, v in value.items() if k not in {"body_html"}}
        if isinstance(value, list):
            return [walk(v, f"{path}[]") for v in value]
        if isinstance(value, str):
            hits = has_prompt_injection(value)
            if hits:
                warnings.append(f"prompt-injection-like text at {path}")
                if block_prompt_injection:
                    return "[BLOCKED_PROMPT_INJECTION_LIKE_TEXT]"
            value = redact(value)
            if len(value) > max_body_chars:
                return value[:max_body_chars] + "...[TRUNCATED]"
            return value
        return value

    return walk(payload), warnings


def read_github(root: Path, repo: str, resource: str, reason: str | None, limit: int | None, allow_prompt_risk: bool) -> int:
    ok, msg, effective_limit, resource = validate_request(root, repo, resource, reason, limit)
    if not ok:
        print(f"[github-guard] BLOCKED: {msg}")
        return 2
    if not which("gh"):
        print("[github-guard] BLOCKED: GitHub CLI `gh` is missing. Run doctor and install from official docs.")
        return 2
    endpoint = RESOURCE_ENDPOINTS[resource].format(repo=repo, limit=effective_limit)
    code, out, err = run_cmd(["gh", "api", endpoint], cwd=root, timeout=120)
    if code != 0:
        print(err or out)
        return code
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        print("[github-guard] ERROR: gh returned non-JSON output")
        return 1
    policy = load_policy(root)
    sanitized, warnings = sanitize_payload(
        payload,
        max_body_chars=int(policy.get("max_body_chars", 20000)),
        block_prompt_injection=policy.get("block_prompt_injection_patterns", True) and not allow_prompt_risk,
    )
    result = {
        "repo": repo,
        "resource": resource,
        "reason": reason,
        "items_requested": effective_limit,
        "warnings": warnings,
        "data": sanitized,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if warnings and not allow_prompt_risk:
        print("[github-guard] prompt-injection-like content was blocked/redacted", flush=True)
    return 0


def check_text(root: Path, file: str | None, text: str | None) -> int:
    if file:
        raw = Path(file).read_text(encoding="utf-8", errors="replace")
    else:
        raw = text or ""
    clean = redact(raw)
    hits = has_prompt_injection(clean)
    result = {
        "prompt_injection_like": bool(hits),
        "patterns": hits,
        "redacted_text": clean,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if hits else 0
