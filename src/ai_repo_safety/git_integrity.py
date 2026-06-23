from __future__ import annotations

from pathlib import Path

from .util import project_root, run_cmd

REWRITE_HINTS = (
    "rebase",
    "reset:",
    "commit (amend):",
    "filter-branch",
    "update by push",
)


def _current_branch(root: Path) -> str | None:
    code, out, _ = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root, timeout=20)
    if code != 0:
        return None
    branch = out.strip()
    return None if branch == "HEAD" else branch


def _has_upstream(root: Path) -> bool:
    code, _, _ = run_cmd(["git", "rev-parse", "--abbrev-ref", "@{upstream}"], cwd=root, timeout=20)
    return code == 0


def collect_integrity_warnings(root: Path) -> list[str]:
    warnings: list[str] = []
    branch = _current_branch(root)
    if branch is None:
        warnings.append("detached HEAD: upstream integrity comparison is limited")
    elif not _has_upstream(root):
        warnings.append(f"branch `{branch}` has no upstream configured")
    else:
        code, out, err = run_cmd(["git", "rev-list", "--left-right", "--count", "HEAD...@{upstream}"], cwd=root, timeout=20)
        if code == 0:
            left, right = [part.strip() for part in out.strip().split()]
            ahead = int(left)
            behind = int(right)
            if ahead and behind:
                warnings.append(f"branch `{branch}` diverged from upstream ({ahead} ahead / {behind} behind)")
        elif err.strip():
            warnings.append(f"could not compare HEAD to upstream: {err.strip()}")

    code, out, _ = run_cmd(["git", "reflog", "-n", "30", "--format=%gs"], cwd=root, timeout=20)
    if code == 0:
        hits = [line for line in out.splitlines() if any(hint in line.lower() for hint in REWRITE_HINTS)]
        if hits:
            warnings.append("recent reflog includes history-rewrite style operations: " + "; ".join(hits[:3]))

    code, _, err = run_cmd(["git", "verify-commit", "HEAD"], cwd=root, timeout=20)
    if code != 0:
        msg = err.strip() or "HEAD commit is not locally verifiable as signed"
        warnings.append(msg)

    code, tag, _ = run_cmd(["git", "describe", "--tags", "--abbrev=0"], cwd=root, timeout=20)
    if code == 0 and tag.strip():
        code, _, err = run_cmd(["git", "verify-tag", tag.strip()], cwd=root, timeout=20)
        if code != 0:
            msg = err.strip() or f"latest tag `{tag.strip()}` is not locally verifiable as signed"
            warnings.append(msg)
    else:
        warnings.append("no reachable tag found from HEAD")

    return warnings


def print_blame_hints(root: Path) -> None:
    print("\n[repo-safety] blame / attribution audit hints:")
    print("  git log --show-signature --decorate -n 20")
    print("  git blame <path>")
    print("  git range-diff @{upstream}...HEAD")
    print(f"  git log --follow -- <path>   # run from {root}")


def audit_git_integrity(target: str | Path) -> int:
    root = project_root(target)
    code, _, err = run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=root, timeout=20)
    if code != 0:
        print(f"[repo-safety] not a git repository: {err.strip() or root}")
        return 2

    warnings = collect_integrity_warnings(root)
    if warnings:
        print("[repo-safety] git integrity warnings:")
        for item in warnings:
            print(f"  - {item}")
        print_blame_hints(root)
        return 1

    print("[repo-safety] git integrity checks passed")
    print_blame_hints(root)
    return 0
