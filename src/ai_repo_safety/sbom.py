"""CycloneDX SBOM command for ai-repo-safety.

The project lists `cyclonedx-py` in its tool philosophy, but it is
NOT a hard runtime dependency. If the user has it installed, we
delegate. Otherwise we print an install plan and return exit 3
(partial / tool-missing) so callers can distinguish it from a
real failure.

The supported scopes map to the actual subcommands of
`cyclonedx-bom` (the package name on PyPI) v7.3.0 released
2026-03-30. The earlier `cyclonedx-py project` invocation we used
in the initial implementation does not exist in v7.x; the closest
"project metadata" inventory is `cyclonedx-bom poetry`, which
requires a `[tool.poetry]` section in pyproject.toml that this
project does not have.

To stay portable, this command defaults to `environment` (which
reads the active Python virtualenv or the system interpreter's
installed distribution set). Users with a requirements.txt file
can pass `--scope requirements`; users with a Poetry manifest can
pass `--scope poetry`. The earlier `--scope project` default was
removed because it pointed at a subcommand that no longer exists.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec
import sys
from pathlib import Path
from typing import Literal

from .util import project_root

# `cyclonedx-bom` is the package name on PyPI. The CLI binary
# installed by `uv tool install cyclonedx-bom` is `cyclonedx-py`.
# This is the same as the older name; the package was renamed in
# 2024 and the binary kept its historical name.
CYCLONEDX_BOM_PYPI = "cyclonedx-bom"
CYCLONEDX_BOM_BINARY = "cyclonedx-py"

CYCLONEDX_PY_HINT = (
    f"Install {CYCLONEDX_BOM_PYPI} to enable the sbom command:\n"
    f"  uv tool install {CYCLONEDX_BOM_PYPI}\n"
    f"or\n"
    f"  pip install {CYCLONEDX_BOM_PYPI}"
)

Scope = Literal["environment", "requirements", "pipenv", "poetry"]
SUPPORTED_SCOPES: tuple[Scope, ...] = ("environment", "requirements", "pipenv", "poetry")


def _ensure_cyclonedx_py() -> str | None:
    """Return the path to the `cyclonedx-py` executable, or None
    if the tool is not on PATH."""
    return shutil.which(CYCLONEDX_BOM_BINARY)


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
    fmt: Literal["cyclonedx-json", "cyclonedx-xml"] = "cyclonedx-json",
    scope: Scope = "environment",
) -> int:
    """Generate a CycloneDX SBOM for the target directory.

    The command is plan-aware: it only writes to the path passed
    via `--output` and never mutates any other file in the target.
    Returns 0 on success, 2 on tool execution error, 3 on
    tool-missing, 4 on configuration error.
    """
    root = project_root(target)
    out_path = (Path.cwd() / output) if not Path(output).is_absolute() else Path(output)

    if fmt not in ("cyclonedx-json", "cyclonedx-xml"):
        print(f"[sbom] unsupported format: {fmt}", file=sys.stderr)
        return 4

    if scope not in SUPPORTED_SCOPES:
        print(
            f"[sbom] unsupported scope: {scope!r}; expected one of {list(SUPPORTED_SCOPES)}",
            file=sys.stderr,
        )
        return 4

    cyclonedx = _ensure_cyclonedx_py()
    if cyclonedx is None:
        print(f"[sbom] {CYCLONEDX_BOM_BINARY} is not installed; cannot generate SBOM.")
        print(CYCLONEDX_PY_HINT)
        return 3

    out_format = "JSON" if fmt == "cyclonedx-json" else "XML"
    out_flag = ["--of", out_format, "--output-file", str(out_path)]

    # `cyclonedx-bom` v7.3.0 subcommand shape:
    #   cyclonedx-py <scope> [options]
    # where <scope> is one of environment/requirements/pipenv/poetry.
    # The earlier draft called `cyclonedx-py project` which is not a
    # real subcommand; this is the v7.3.0-correct invocation.
    cmd = [cyclonedx, scope, *out_flag, str(root)]

    code, _out, err = _run_cyclonedx(cmd, cwd=root)
    if code != 0:
        print(f"[sbom] {CYCLONEDX_BOM_BINARY} exited with code {code}", file=sys.stderr)
        if err:
            print(err, file=sys.stderr)
        return 2
    print(f"[sbom] wrote {out_path} (scope={scope}, format={fmt})")
    return 0


__all__ = [
    "CYCLONEDX_BOM_PYPI",
    "CYCLONEDX_BOM_BINARY",
    "CYCLONEDX_PY_HINT",
    "SUPPORTED_SCOPES",
    "Scope",
    "generate_sbom",
]
