"""Audit Python dependencies from lockfiles, never from the CLI interpreter.

Order:
1. ``uv.lock`` via ``osv-scanner scan source --lockfile``
2. ``uv export --frozen --no-dev`` + ``pip-audit -r --disable-pip``
3. ``requirements.txt`` / ``pylock.toml`` via the same ``pip-audit -r`` path

Bare ``pip-audit`` against ``sys.executable`` / ``PIPAPI_PYTHON_LOCATION`` is
intentionally not used: that audited the skill's own environment.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from .util import project_root, run_cmd, which

PIP_AUDIT_UVX = ["uvx", "--with", "msgpack>=1.2.1", "pip-audit"]


def _is_python_repo(root: Path) -> bool:
    return (root / "pyproject.toml").exists() or (root / "requirements.txt").exists()


def _pip_audit_cmd() -> list[str] | None:
    if which("pip-audit"):
        return ["pip-audit"]
    if which("uvx"):
        return list(PIP_AUDIT_UVX)
    return None


def _run_pip_audit_requirements(req_file: Path, *, cwd: Path) -> tuple[int, str]:
    cmd = _pip_audit_cmd()
    if cmd is None:
        return 2, "[repo-safety] blocking: required scanner `pip-audit` is missing"
    hashed = ["-r", str(req_file), "--disable-pip"]
    code, out, err = run_cmd([*cmd, *hashed], cwd=cwd, timeout=300)
    if code == 0:
        return 0, ""
    # --disable-pip requires hashes or fully pinned files. Retry in
    # requirements mode without pip-API-on-the-CLI-env.
    if "--disable-pip" in (err or "") or "disable-pip" in (err or "") or code not in (0, 127):
        code2, out2, err2 = run_cmd([*cmd, "-r", str(req_file)], cwd=cwd, timeout=300)
        if code2 == 0:
            return 0, ""
        detail = (err2 or out2 or err or out).strip()
        return (2 if code2 == 127 else 1), detail
    if code == 127:
        return 2, "[repo-safety] blocking: required scanner `pip-audit` is missing"
    return 1, (err or out).strip()


def _run_osv_lockfile(lockfile: Path, *, cwd: Path, offline: bool) -> tuple[int, str]:
    cmd = ["osv-scanner", "scan", "source", "--lockfile", str(lockfile)]
    if offline:
        cmd.append("--offline")
    code, out, err = run_cmd(cmd, cwd=cwd, timeout=300)
    if code == 0:
        return 0, ""
    if code == 127:
        return 127, "[repo-safety] blocking: required scanner `osv-scanner` is missing"
    return 1, (err or out).strip()


def _export_uv_lock(root: Path) -> tuple[Path | None, str]:
    if not which("uv"):
        return None, "[repo-safety] `uv` is missing; cannot export uv.lock"
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False, encoding="utf-8"
    )
    handle.close()
    dest = Path(handle.name)
    cmd = [
        "uv",
        "export",
        "--frozen",
        "--no-dev",
        "--no-emit-project",
        "-o",
        str(dest),
    ]
    code, out, err = run_cmd(cmd, cwd=root, timeout=180)
    if code != 0:
        dest.unlink(missing_ok=True)
        return None, (err or out or "uv export failed").strip()
    return dest, ""


def audit_lockfile(
    target: str | Path,
    *,
    required: bool = False,
    offline: bool = False,
) -> tuple[int, str]:
    """Return ``(exit_code, detail)``.

    Exit codes match the CLI: 0 ok, 1 findings, 2 tool error.
    When ``required`` is false, missing inputs skip (0). When true,
    a Python repo without an auditable lockfile fails.
    """
    root = project_root(target)
    uv_lock = root / "uv.lock"
    reqs = root / "requirements.txt"
    pylock = root / "pylock.toml"

    if offline and required:
        return 2, "[repo-safety] lockfile audit requires network (refusing --offline on a required gate)"
    if offline:
        return 0, "skipped lockfile audit (offline)"

    if uv_lock.exists():
        if which("osv-scanner"):
            code, detail = _run_osv_lockfile(uv_lock, cwd=root, offline=False)
            if code == 0:
                return 0, "osv-scanner uv.lock"
            if code != 127:
                return code, detail
        exported, export_err = _export_uv_lock(root)
        if exported is None:
            if required:
                if not which("osv-scanner"):
                    return 2, "[repo-safety] blocking: required scanner `osv-scanner` is missing and uv export failed: " + export_err
                return 2, export_err
            return 0, export_err
        try:
            return _run_pip_audit_requirements(exported, cwd=root)
        finally:
            exported.unlink(missing_ok=True)

    for path in (pylock, reqs):
        if path.exists():
            if path.suffix == ".toml" and path.name == "pylock.toml":
                if which("osv-scanner"):
                    code, detail = _run_osv_lockfile(path, cwd=root, offline=False)
                    if code != 127:
                        return code, detail
            return _run_pip_audit_requirements(path, cwd=root)

    if required and _is_python_repo(root):
        return 2, "[repo-safety] blocking: no uv.lock / pylock.toml / requirements.txt to audit"
    return 0, "skipped lockfile audit (no lockfile)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit Python lockfiles (not the CLI environment).")
    parser.add_argument("target", nargs="?", default=".")
    parser.add_argument("--required", action="store_true")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args(argv)
    code, detail = audit_lockfile(args.target, required=args.required, offline=args.offline)
    if detail:
        stream = sys.stderr if code else sys.stdout
        print(detail, file=stream)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
