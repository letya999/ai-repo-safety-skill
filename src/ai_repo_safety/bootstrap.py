from __future__ import annotations

import shutil
from pathlib import Path

from .util import (
    append_marked_block,
    asset_text,
    detect_github_project,
    detect_python_project,
    dump_json,
    git_origin,
    parse_github_repo_from_url,
    project_root,
    write_text,
)

DEFAULT_POLICY = {
    "version": 1,
    "github_read_guard": {
        "mode": "strict",
        "allowed_repositories": [],
        "allowed_resources": ["issues", "pulls", "branches", "commits"],
        "resource_aliases": {"mrs": "pulls", "merge_requests": "pulls", "prs": "pulls"},
        "require_explicit_reason": True,
        "max_items": 30,
        "max_body_chars": 20000,
        "redact_secrets": True,
        "block_prompt_injection_patterns": True,
        "deny_cross_repo_reads": True,
    },
    "secret_files": [
        ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519",
        "credentials*.json", "service-account*.json", "token.json", "tokens.json", "secrets.json",
        ".mcp.json", "claude_desktop_config.json", "*.ovpn",
    ],
}


def copy_asset(relative_asset: str, target: Path, *, overwrite: bool = False) -> bool:
    return write_text(target, asset_text(relative_asset), overwrite=overwrite)


def apply_universal(root: Path, *, overwrite: bool = False) -> list[str]:
    actions: list[str] = []

    block = asset_text("templates/universal/gitignore.block")
    status = append_marked_block(root / ".gitignore", "AI REPO SAFETY", block)
    actions.append(f".gitignore {status}")

    if copy_asset("templates/universal/env.example", root / ".env.example", overwrite=overwrite):
        actions.append("created .env.example")
    else:
        actions.append("kept existing .env.example")

    if copy_asset("templates/universal/AGENTS.md", root / "AGENTS.md", overwrite=overwrite):
        actions.append("created AGENTS.md")
    else:
        status = append_marked_block(root / "AGENTS.md", "AI REPO SAFETY RULES", asset_text("templates/universal/AGENTS.append.md"))
        actions.append(f"AGENTS.md {status}")

    for asset, dest in [
        ("templates/universal/SECURITY.md", "SECURITY.md"),
        ("templates/universal/pre-commit-config.yaml", ".pre-commit-config.yaml"),
        ("docs/mcp-safety.md", "docs/mcp-safety.md"),
        ("docs/incident-cleanup.md", "docs/incident-cleanup.md"),
        ("docs/git-history-cleanup.md", "docs/git-history-cleanup.md"),
        ("docs/mitigation-map.md", "docs/mitigation-map.md"),
    ]:
        path = root / dest
        if path.exists() and not overwrite and dest == ".pre-commit-config.yaml":
            alt = root / ".pre-commit-config.ai-repo-safety.yaml"
            copy_asset(asset, alt, overwrite=True)
            actions.append("existing .pre-commit-config.yaml found; wrote .pre-commit-config.ai-repo-safety.yaml")
        elif copy_asset(asset, path, overwrite=overwrite):
            actions.append(f"created {dest}")
        else:
            actions.append(f"kept existing {dest}")

    scripts = [
        "forbid_sensitive_files.py",
        "prepush.py",
        "scan_mcp_config.py",
        "github_read_guard.py",
        "scan_secrets.py",
    ]
    for name in scripts:
        copy_asset(f"scripts/{name}", root / "scripts" / "security" / name, overwrite=True)
        actions.append(f"installed scripts/security/{name}")

    policy_path = root / ".repo-safety.json"
    policy = DEFAULT_POLICY.copy()
    current_repo = parse_github_repo_from_url(git_origin(root))
    if current_repo:
        policy["github_read_guard"]["allowed_repositories"] = [current_repo]
    if not policy_path.exists() or overwrite:
        dump_json(policy_path, policy)
        actions.append("created .repo-safety.json")
    else:
        actions.append("kept existing .repo-safety.json")

    return actions


def apply_python(root: Path, *, overwrite: bool = False) -> list[str]:
    actions: list[str] = []
    for asset, dest in [
        ("templates/python/bandit.yaml", "bandit.yaml"),
        ("templates/python/pyproject.ai-repo-safety.toml", "pyproject.ai-repo-safety.toml"),
        ("templates/python/settings.py", "src/app/settings.py"),
        ("templates/python/test_security_basics.py", "tests/test_security_basics.py"),
    ]:
        if copy_asset(asset, root / dest, overwrite=overwrite):
            actions.append(f"created {dest}")
        else:
            actions.append(f"kept existing {dest}")
    return actions


def apply_github(root: Path, *, overwrite: bool = False) -> list[str]:
    actions: list[str] = []
    workflow_assets = [
        "security.yml",
        "sast.yml",
        "supply-chain.yml",
        "scorecard.yml",
        "codeql.optional.yml",
    ]
    for name in workflow_assets:
        if copy_asset(f"workflows/{name}", root / ".github" / "workflows" / name, overwrite=overwrite):
            actions.append(f"created .github/workflows/{name}")
        else:
            actions.append(f"kept existing .github/workflows/{name}")
    for asset, dest in [
        ("templates/github/renovate.json", "renovate.json"),
        ("templates/github/pull_request_template.md", ".github/pull_request_template.md"),
        ("templates/github/security_review_issue.md", ".github/ISSUE_TEMPLATE/security_review.md"),
        ("templates/github/CODEOWNERS.example", ".github/CODEOWNERS.example"),
    ]:
        if copy_asset(asset, root / dest, overwrite=overwrite):
            actions.append(f"created {dest}")
        else:
            actions.append(f"kept existing {dest}")
    return actions


def apply_rules(root: Path, *, overwrite: bool = False) -> list[str]:
    actions: list[str] = []
    for name in [
        "python-dangerous-code.yml",
        "python-fastapi-security.yml",
        "ai-agent-dangerous-patterns.yml",
        "mcp-config-security.yml",
        "github-actions-security.yml",
        "secrets-adjacent.yml",
    ]:
        copy_asset(f"rules/opengrep/{name}", root / ".repo-safety" / "opengrep" / name, overwrite=True)
        actions.append(f"installed .repo-safety/opengrep/{name}")
    return actions


def init_project(target: str | Path, *, python: str = "auto", github: str = "auto", overwrite: bool = False) -> int:
    root = project_root(target)
    root.mkdir(parents=True, exist_ok=True)
    actions: list[str] = []
    actions.extend(apply_universal(root, overwrite=overwrite))
    actions.extend(apply_rules(root, overwrite=overwrite))

    python_enabled = detect_python_project(root) if python == "auto" else python == "yes"
    github_enabled = detect_github_project(root) if github == "auto" else github == "yes"

    if python_enabled:
        actions.extend(apply_python(root, overwrite=overwrite))
    else:
        actions.append("python profile skipped")

    if github_enabled:
        actions.extend(apply_github(root, overwrite=overwrite))
    else:
        actions.append("github profile skipped")

    print("AI Repo Safety initialized:")
    for action in actions:
        print(f"- {action}")
    print()
    print("Next:")
    print(f"  ai-repo-safety install-hooks --target {root}")
    print(f"  ai-repo-safety scan --target {root}")
    return 0
