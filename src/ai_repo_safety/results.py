"""Structured result types for the ai-repo-safety CLI.

Exit code contract (intentionally narrow so callers can rely on
discrete values rather than the historical "0/1/2 means whatever
the previous release felt like"):

- 0  success / all required checks passed
- 1  findings detected
- 2  tool execution error (subprocess failure, missing input, etc.)
- 3  partial scan: at least one optional tool was missing or
       skipped under a strict policy
- 4  configuration or policy violation (the caller asked for
       something the active policy forbids)
- 5  internal error (unexpected exception, programmer error)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Status = Literal["ok", "passed", "failed", "partial", "skipped", "error"]
Severity = Literal["info", "low", "medium", "high", "critical"]
FindingCategory = Literal[
    "forbidden_file",
    "secret_content",
    "secret_placeholder",
    "policy_violation",
    "tool_error",
    "internal",
]


@dataclass
class ToolRun:
    """A single subprocess invocation the scan orchestrated."""

    name: str
    command: list[str]
    status: Status
    exit_code: int | None = None
    required: bool = False
    reason: str | None = None


@dataclass
class Finding:
    """A single security finding emitted by any tool or rule."""

    id: str
    severity: Severity
    category: FindingCategory
    message: str
    file: str | None = None
    line: int | None = None
    tool: str | None = None
    redacted: bool = True


@dataclass
class ScanReport:
    """Aggregated scan result.

    `exit_code` is the single integer the CLI should return to the
    shell. See the module docstring for the contract.
    """

    status: Status
    target: str
    tools: list[ToolRun] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def exit_code(self, *, strict: bool = False) -> int:
        if self.errors:
            return 2
        if self.findings:
            return 1
        if self.status == "partial":
            return 3 if strict else 0
        if self.status == "error":
            return 2
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "target": self.target,
            "tools": [
                {
                    "name": t.name,
                    "command": t.command,
                    "status": t.status,
                    "exit_code": t.exit_code,
                    "required": t.required,
                    "reason": t.reason,
                }
                for t in self.tools
            ],
            "findings": [
                {
                    "id": f.id,
                    "severity": f.severity,
                    "category": f.category,
                    "message": f.message,
                    "file": f.file,
                    "line": f.line,
                    "tool": f.tool,
                    "redacted": f.redacted,
                }
                for f in self.findings
            ],
            "errors": self.errors,
            "warnings": self.warnings,
        }


__all__ = [
    "Status",
    "Severity",
    "FindingCategory",
    "ToolRun",
    "Finding",
    "ScanReport",
]
