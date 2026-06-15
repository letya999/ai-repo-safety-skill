"""Structured JSON and SARIF output for `ai-repo-safety scan`.

The default text path is unchanged: it prints human-readable
status lines and returns the integer exit code. The structured
paths wrap the same scanners and emit a machine-readable
representation of the result for CI ingestion.
"""

from __future__ import annotations

import json
import subprocess  # nosec
import sys
from pathlib import Path

from .fast_scan import scan_directory
from .results import Finding, ScanReport, Status, ToolRun
from .util import detect_python_project, git_has_commits, project_root, which


def _tool(name: str, command: list[str], *, status: Status = "skipped", required: bool = False) -> ToolRun:
    return ToolRun(
        name=name,
        command=command,
        status=status,
        required=required,
        reason="missing" if not which(name) else None,
    )


def _run_subprocess(name: str, command: list[str], *, required: bool, offline: bool) -> ToolRun:
    if not which(name):
        return _tool(name, command, status="skipped", required=required)
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=300)  # nosec
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return ToolRun(name=name, command=command, status="error", required=required, reason=str(exc))
    if proc.returncode != 0:
        return ToolRun(name=name, command=command, status="failed", exit_code=proc.returncode, required=required)
    return ToolRun(name=name, command=command, status="passed", exit_code=proc.returncode, required=required)


def _collect_report(target: str | Path, *, strict: bool, offline: bool) -> ScanReport:
    root = project_root(target)
    report = ScanReport(status="passed", target=str(root))

    for finding in scan_directory(root):
        report.findings.append(
            Finding(
                id=f"{finding.get('type', 'unknown')}@{finding.get('file', '?')}:{finding.get('line', 0)}",
                severity="high",
                category=(
                    "forbidden_file"
                    if finding.get("type") == "forbidden_file"
                    else "secret_placeholder" if finding.get("type") == "secret_placeholder" else "secret_content"
                ),
                message=str(finding.get("message", "")),
                file=str(finding.get("file", "")) or None,
                line=finding.get("line"),
                tool="fast_scan",
            )
        )

    if which("gitleaks"):
        report.tools.append(
            _run_subprocess(
                "gitleaks",
                ["gitleaks", "detect", "--source", str(root), "--redact", "--exit-code", "1"],
                required=strict,
                offline=offline,
            )
        )
    else:
        report.tools.append(_tool("gitleaks", ["gitleaks"], required=strict))

    if git_has_commits(root):
        trufflehog_cmd = [
            "trufflehog",
            "git",
            f"file://{root}",
            "--results=verified,unknown",
            "--fail",
        ]
    else:
        trufflehog_cmd = ["trufflehog", "filesystem", str(root), "--results=verified,unknown", "--fail"]
    if which("trufflehog"):
        report.tools.append(_run_subprocess("trufflehog", trufflehog_cmd, required=strict, offline=offline))
    else:
        report.tools.append(_tool("trufflehog", trufflehog_cmd, required=strict))

    if detect_python_project(root):
        for tool, cmd in (
            ("bandit", ["bandit", "-q", "-r", str(root / "src"), "-x", "tests"]),
            ("ruff", ["ruff", "check", str(root)]),
        ):
            if which(tool):
                report.tools.append(_run_subprocess(tool, cmd, required=False, offline=offline))
            else:
                report.tools.append(_tool(tool, cmd, required=False))

        if offline:
            report.tools.append(
                ToolRun(
                    name="pip-audit",
                    command=["pip-audit"],
                    status="skipped",
                    required=False,
                    reason="network_required",
                )
            )
        elif which("pip-audit"):
            report.tools.append(_run_subprocess("pip-audit", ["pip-audit"], required=False, offline=offline))
        else:
            report.tools.append(
                ToolRun(
                    name="pip-audit",
                    command=["pip-audit"],
                    status="skipped",
                    required=False,
                    reason="missing",
                )
            )

    failed = [t for t in report.tools if t.status == "failed"]
    skipped = [t for t in report.tools if t.status == "skipped"]
    if failed:
        report.status = "failed"
    elif skipped:
        report.status = "partial"
    return report


def emit_scan(target: str | Path, *, strict: bool = False, offline: bool = False, sarif: bool = False) -> int:
    report = _collect_report(target, strict=strict, offline=offline)
    if sarif:
        sarif_doc = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ai-repo-safety",
                            "version": "0.1.3",
                            "informationUri": "https://github.com/letya999/ai-repo-safety-skill",
                            "rules": [],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.id,
                            "level": "error" if f.severity in {"high", "critical"} else "warning",
                            "message": {"text": f.message},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.file or "."},
                                        "region": {"startLine": f.line or 1} if f.line else {},
                                    }
                                }
                            ]
                            if f.file
                            else [],
                        }
                        for f in report.findings
                    ],
                }
            ],
        }
        sys.stdout.write(json.dumps(sarif_doc, indent=2, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n")
    return report.exit_code(strict=strict)


__all__ = ["emit_scan"]
