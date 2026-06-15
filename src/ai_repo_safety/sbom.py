"""CycloneDX SBOM command for ai-repo-safety.

The project lists `cyclonedx-py` in its tool philosophy, but it is
NOT a hard runtime dependency. If the user has it installed, we
delegate. Otherwise we print an install plan and return a partial
status (exit 3 in strict mode, exit 0 in default mode).

Verification path is documented in the function docstring of
generate_sbom below.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec
import sys
from pathlib import Path

from .util import project_root

CYCLONEDX_PY_HINT = (
    "Install cyclonedx-py to enable the sbom command:\n"
    "  uv tool install cyclonedx-py\n"
    "or\n"
    "  pip install cyclonedx-py"
)


def _ensure_cyclonedx_py() -> str | None:
    """Return the path to the cyclonedx-py executable, or None if
    the tool is not on PATH."""
    return shutil.which("cyclonedx-py")


def _run_cyclonedx(args: list[str], *, cwd: Path) -> tuple[int, str, str]:
    proc = subprocess.run(  # nosec
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    return proc.returncode, proc.stdout, proc.stderr


def generate_sbom(
    target: str | Path,
    *,
    output: str = "sbom.cdx.json",
    fmt: str = "cyclonedx-json",
    scope: str = "project",
) -> int:
    """Generate a CycloneDX SBOM for the target directory.

    The command is plan-aware: it only writes to the path passed
    via --output and never mutates any other file in the target.
    """
    root = project_root(target)
    out_path = (Path.cwd() / output) if not Path(output).is_absolute() else Path(output)

    if fmt not in {"cyclonedx-json", "cyclonedx-xml"}:
        print(f"[sbom] unsupported format: {fmt}", file=sys.stderr)
        return 4

    cyclonedx = _ensure_cyclonedx_py()
    if cyclonedx is None:
        print("[sbom] cyclonedx-py is not installed; cannot generate SBOM.")
        print(CYCLONEDX_PY_HINT)
        return 3  # partial: tool missing under user-facing failure mode

    out_format = "JSON" if fmt == "cyclonedx-json" else "XML"
    out_flag = ["--of", out_format, "--output-file", str(out_path)]
    if scope == "project":
        cmd = [cyclonedx, "project", *out_flag, str(root)]
    else:
        cmd = [cyclonedx, "environment", *out_flag]

    code, _out, err = _run_cyclonedx(cmd, cwd=root)
    if code != 0:
        print(f"[sbom] cyclonedx-py exited with code {code}", file=sys.stderr)
        if err:
            print(err, file=sys.stderr)
        return 2
    print(f"[sbom] wrote {out_path} (scope={scope}, format={fmt})")
    return 0


__all__ = ["generate_sbom", "CYCLONEDX_PY_HINT"]
