"""Unified fail-closed gates for commit, push, tag, and GitHub reads.

Git hooks are the source of hardness. This module is what those hooks
exec. Agent PreToolUse hooks call the same profiles as an early warning.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from importlib.resources import as_file, files
from pathlib import Path

from .util import load_repo_policy, project_root, run_cmd, which

WHEN_CHOICES = ("commit", "push", "tag", "github-read", "auto")


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    exit_code: int = 0


@dataclass
class GateReport:
    when: str
    target: str
    checks: list[Check] = field(default_factory=list)
    exit_code: int = 0

    def to_json(self) -> dict:
        return {
            "when": self.when,
            "target": self.target,
            "ok": self.exit_code == 0,
            "exit_code": self.exit_code,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status,
                    "detail": c.detail,
                    "exit_code": c.exit_code,
                }
                for c in self.checks
            ],
        }


def classify_pre_push_stdin(text: str) -> tuple[str, str | None]:
    """Parse git pre-push lines into ``(when, tag_version)``.

    Any ``refs/tags/*`` remote ref selects the tag gate. The first
    tag name is returned with a leading ``v`` stripped when it looks
    like a semver tag.
    """
    when = "push"
    version: str | None = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        remote_ref = parts[2]
        if remote_ref.startswith("refs/tags/"):
            when = "tag"
            tag = remote_ref[len("refs/tags/") :]
            if version is None:
                version = _tag_to_version(tag)
    return when, version


def _tag_to_version(tag: str) -> str:
    if tag.startswith("v") and len(tag) > 1 and tag[1].isdigit():
        return tag[1:]
    return tag


def _log(message: str, *, json_out: bool) -> None:
    print(message, file=sys.stderr if json_out else sys.stdout)


def _log_err(message: str) -> None:
    print(message, file=sys.stderr)


def _python() -> list[str]:
    return [sys.executable]


def _helper_script(root: Path, name: str) -> str | None:
    for rel in (f".repo-safety/scripts/{name}", f"scripts/security/{name}"):
        if (root / rel).exists():
            return rel
    return None


def _run_packaged_or_helper(
    root: Path, name: str, args: list[str]
) -> tuple[int, str, str]:
    rel = _helper_script(root, name)
    if rel:
        return run_cmd(_python() + [rel, *args], cwd=root, timeout=120)
    traversable = files("ai_repo_safety") / "assets" / "scripts" / name
    with as_file(traversable) as path:
        return run_cmd(_python() + [str(path), *args], cwd=root, timeout=120)


def _missing(tool: str) -> str:
    return f"[repo-safety] blocking: required scanner `{tool}` is missing"


def _record(report: GateReport, name: str, code: int, detail: str = "") -> None:
    if code == 0:
        status = "passed"
    elif code == 127:
        status = "error"
        code = 2
        detail = detail or _missing(name)
    elif code == 2:
        status = "error"
    else:
        status = "failed"
        code = 1
    report.checks.append(Check(name=name, status=status, detail=detail, exit_code=code))
    if code and report.exit_code == 0:
        report.exit_code = code
    elif code == 2 and report.exit_code == 1:
        report.exit_code = 2


def _run_sensitive_files(root: Path, *, staged: bool, report: GateReport, json_out: bool) -> None:
    args: list[str] = [] if staged else ["--all"]
    _log("[repo-safety] checking sensitive files" + (" (staged)" if staged else ""), json_out=json_out)
    code, out, err = _run_packaged_or_helper(root, "forbid_sensitive_files.py", args)
    detail = (out or err).strip()
    if detail:
        _log(detail, json_out=json_out)
        if code:
            _log_err(detail)
    _record(report, "sensitive-files", code, detail)


def _run_mcp(root: Path, report: GateReport, json_out: bool) -> None:
    _log("[repo-safety] scanning MCP config", json_out=json_out)
    code, out, err = _run_packaged_or_helper(root, "scan_mcp_config.py", [])
    detail = (out or err).strip()
    if detail:
        _log(detail, json_out=json_out)
        if code:
            _log_err(detail)
    _record(report, "mcp-config", code, detail)


def _run_gitleaks(root: Path, *, staged: bool, report: GateReport, json_out: bool) -> None:
    if not which("gitleaks"):
        msg = _missing("gitleaks")
        _log(msg, json_out=json_out)
        _log_err(msg)
        _record(report, "gitleaks", 2, msg)
        return
    if staged:
        cmd = [
            "gitleaks",
            "protect",
            "--staged",
            "--redact",
            "--no-banner",
            "--source",
            ".",
            "--exit-code",
            "1",
        ]
    else:
        cmd = [
            "gitleaks",
            "detect",
            "--source",
            ".",
            "--redact",
            "--no-banner",
            "--exit-code",
            "1",
        ]
    _log("[repo-safety] running: " + " ".join(cmd), json_out=json_out)
    code, out, err = run_cmd(cmd, cwd=root, timeout=300)
    detail = (err or out).strip()
    if detail:
        _log(detail, json_out=json_out)
        if code:
            _log_err(detail)
    if code == 127:
        msg = _missing("gitleaks")
        _log_err(msg)
        _record(report, "gitleaks", 2, msg)
        return
    _record(report, "gitleaks", code, detail)


def _run_trufflehog(root: Path, report: GateReport, json_out: bool) -> None:
    from .scanner import _resolve_trufflehog_since_commit, _trufflehog_exclude_args, git_has_commits

    if not which("trufflehog"):
        msg = "[repo-safety] WARN: missing tool `trufflehog`; run `ai-repo-safety doctor --agent-plan`"
        _log(msg, json_out=json_out)
        report.checks.append(Check(name="trufflehog", status="skipped", detail=msg, exit_code=0))
        return
    if git_has_commits(root):
        since = _resolve_trufflehog_since_commit(root)
        if since:
            cmd = [
                "trufflehog",
                "git",
                "file://.",
                "--no-update",
                "--since-commit",
                since,
                *_trufflehog_exclude_args(root),
                "--results=verified,unknown",
                "--fail",
            ]
        else:
            cmd = [
                "trufflehog",
                "filesystem",
                ".",
                "--no-update",
                *_trufflehog_exclude_args(root),
                "--results=verified,unknown",
                "--fail",
            ]
    else:
        cmd = [
            "trufflehog",
            "filesystem",
            ".",
            "--no-update",
            *_trufflehog_exclude_args(root),
            "--results=verified,unknown",
            "--fail",
        ]
    _log("[repo-safety] running: " + " ".join(cmd), json_out=json_out)
    code, out, err = run_cmd(cmd, cwd=root, timeout=300)
    detail = (err or out).strip()
    if detail:
        _log(detail, json_out=json_out)
        if code:
            _log_err(detail)
    if code == 127:
        report.checks.append(
            Check(name="trufflehog", status="skipped", detail=_missing("trufflehog"), exit_code=0)
        )
        return
    _record(report, "trufflehog", code, detail)


def _run_lockfile(root: Path, report: GateReport, *, required: bool, offline: bool, json_out: bool) -> None:
    from .lockfile_audit import audit_lockfile

    _log("[repo-safety] auditing lockfile", json_out=json_out)
    code, detail = audit_lockfile(root, required=required, offline=offline)
    if detail:
        _log(detail, json_out=json_out)
        if code:
            _log_err(detail)
    _record(report, "lockfile", code, detail)


def _should_verify_release(root: Path) -> bool:
    policy = load_repo_policy(root)
    release = policy.get("release") if isinstance(policy.get("release"), dict) else {}
    gates = policy.get("gates") if isinstance(policy.get("gates"), dict) else {}
    gate_release = gates.get("release") if isinstance(gates.get("release"), dict) else {}
    if release.get("verify_version") or gate_release.get("verify_version"):
        return True
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return False
    try:
        import tomllib

        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return data.get("project", {}).get("name") == "ai-repo-safety"


def _push_lockfile_enabled(root: Path) -> bool:
    policy = load_repo_policy(root)
    gates = policy.get("gates") if isinstance(policy.get("gates"), dict) else {}
    push = gates.get("push") if isinstance(gates.get("push"), dict) else {}
    return bool(push.get("lockfile"))


def _run_commit(root: Path, report: GateReport, json_out: bool) -> None:
    _run_sensitive_files(root, staged=True, report=report, json_out=json_out)
    if report.exit_code:
        return
    _run_gitleaks(root, staged=True, report=report, json_out=json_out)


def _run_push(root: Path, report: GateReport, *, offline: bool, json_out: bool) -> None:
    _run_sensitive_files(root, staged=False, report=report, json_out=json_out)
    if report.exit_code:
        return
    _run_mcp(root, report, json_out)
    if report.exit_code:
        return
    _run_gitleaks(root, staged=False, report=report, json_out=json_out)
    if report.exit_code:
        return
    _run_trufflehog(root, report, json_out)
    if report.exit_code:
        return
    if _push_lockfile_enabled(root):
        _run_lockfile(root, report, required=True, offline=offline, json_out=json_out)


def _run_tag(
    root: Path,
    report: GateReport,
    *,
    offline: bool,
    json_out: bool,
    version: str | None,
) -> None:
    _run_push(root, report, offline=offline, json_out=json_out)
    if report.exit_code:
        return
    _run_lockfile(root, report, required=True, offline=offline, json_out=json_out)
    if report.exit_code:
        return
    if not _should_verify_release(root):
        return
    if not version:
        msg = "[repo-safety] blocking: tag gate needs --version for verify-release"
        _log(msg, json_out=json_out)
        _log_err(msg)
        _record(report, "verify-release", 2, msg)
        return
    from .verify_release import verify_release

    _log(f"[repo-safety] verify-release --version {version}", json_out=json_out)
    code = verify_release(root, version, skip_build=False)
    _record(report, "verify-release", code, "" if code == 0 else "verify-release failed")


def _run_github_read(
    root: Path,
    report: GateReport,
    *,
    json_out: bool,
    repo: str | None,
    resource: str | None,
    reason: str | None,
    limit: int | None,
    allow_prompt_injection_risk: bool,
) -> None:
    if not repo or not resource or not reason:
        msg = (
            "[repo-safety] blocking: github-read requires --repo, --resource, and --reason. "
            'Example: python -m ai_repo_safety gate --when github-read --repo owner/repo '
            '--resource pulls --reason "review current PRs"'
        )
        _log(msg, json_out=json_out)
        _log_err(msg)
        _record(report, "github-read", 2, msg)
        return
    from .github_guard import read_github

    code = read_github(root, repo, resource, reason, limit, allow_prompt_injection_risk)
    _record(report, "github-read", code, "" if code == 0 else "github-guard blocked or failed")


def run_gate(
    target: str | Path,
    *,
    when: str,
    json_out: bool = False,
    offline: bool = False,
    repo: str | None = None,
    resource: str | None = None,
    reason: str | None = None,
    limit: int | None = None,
    allow_prompt_injection_risk: bool = False,
    version: str | None = None,
    stdin_text: str | None = None,
) -> int:
    if when not in WHEN_CHOICES:
        print(f"[repo-safety] unknown gate: {when}", file=sys.stderr)
        return 2

    root = project_root(target)
    if when == "auto":
        raw = stdin_text if stdin_text is not None else sys.stdin.read()
        when, parsed = classify_pre_push_stdin(raw)
        version = version or parsed

    report = GateReport(when=when, target=str(root))
    if when == "commit":
        _run_commit(root, report, json_out)
    elif when == "push":
        _run_push(root, report, offline=offline, json_out=json_out)
    elif when == "tag":
        _run_tag(root, report, offline=offline, json_out=json_out, version=version)
    elif when == "github-read":
        _run_github_read(
            root,
            report,
            json_out=json_out,
            repo=repo,
            resource=resource,
            reason=reason,
            limit=limit,
            allow_prompt_injection_risk=allow_prompt_injection_risk,
        )

    if json_out:
        print(json.dumps(report.to_json(), indent=2, ensure_ascii=False))
    elif report.exit_code == 0:
        _log(f"[repo-safety] {when} gate passed", json_out=False)
    else:
        _log(f"[repo-safety] {when} gate blocked", json_out=False)
        _log_err(f"[repo-safety] {when} gate blocked")
    return report.exit_code
