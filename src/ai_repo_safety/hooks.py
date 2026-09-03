from __future__ import annotations

import stat
from pathlib import Path

from .util import project_root, write_text

# Public markers delimiting the blocks of git hooks that
# ai-repo-safety manages. The two non-ascii character classes are
# deliberately chosen so they are extremely unlikely to collide with
# any pre-existing hook an end user wrote by hand.
PRE_PUSH_MARKER = "AI REPO SAFETY PRE-PUSH"
PRE_COMMIT_MARKER = "AI REPO SAFETY PRE-COMMIT"


def _posix_gate_hook(when: str, marker: str, *, fallthrough: bool = False) -> str:
    """POSIX hook body used on Linux, macOS, and Git for Windows.

    Git for Windows runs ``.git/hooks/pre-commit`` / ``pre-push`` through
    bash. It never executes a sibling ``*.cmd`` as a hook.

    Interpreters are probed with ``import ai_repo_safety.gate`` *before*
    running the gate so a failed gate (exit 1) cannot fall through to
    the next launcher. Missing CLI always refuses (exit 1).

    ``fallthrough=True`` is for --chain: the gate runs first, and only
    if it passes does the rest of the hook file run. That is required
    because pre-commit and many custom hooks ``exec``, which would skip
    a block appended after them.
    """
    if fallthrough:
        try_body = """  "$@" -m ai_repo_safety gate --when "$WHEN" --target .
  code=$?
  if [ "$code" -ne 0 ]; then
    exit "$code"
  fi
  RAN=1
  return 0"""
        tail = """if [ "$RAN" -eq 0 ] && command -v uvx >/dev/null 2>&1; then
  uvx ai-repo-safety gate --when "$WHEN" --target .
  code=$?
  if [ "$code" -ne 0 ]; then
    exit "$code"
  fi
  RAN=1
fi
if [ "$RAN" -eq 0 ] && command -v ai-repo-safety >/dev/null 2>&1; then
  ai-repo-safety gate --when "$WHEN" --target .
  code=$?
  if [ "$code" -ne 0 ]; then
    exit "$code"
  fi
  RAN=1
fi
if [ "$RAN" -eq 0 ]; then
  echo "[repo-safety] ai-repo-safety not found; refusing $WHEN" >&2
  echo "[repo-safety] install and retry with one of:" >&2
  echo "[repo-safety]   py -3 -m ai_repo_safety gate --when $WHEN --target ." >&2
  echo "[repo-safety]   python -m ai_repo_safety gate --when $WHEN --target ." >&2
  echo "[repo-safety]   uvx ai-repo-safety gate --when $WHEN --target ." >&2
  exit 1
fi"""
        ran_init = "RAN=0\n"
        skip_if_ran = """  if [ "$RAN" -ne 0 ]; then
    return 0
  fi
"""
    else:
        try_body = '  exec "$@" -m ai_repo_safety gate --when "$WHEN" --target .'
        tail = """if command -v uvx >/dev/null 2>&1; then
  exec uvx ai-repo-safety gate --when "$WHEN" --target .
fi
if command -v ai-repo-safety >/dev/null 2>&1; then
  exec ai-repo-safety gate --when "$WHEN" --target .
fi
echo "[repo-safety] ai-repo-safety not found; refusing $WHEN" >&2
echo "[repo-safety] install and retry with one of:" >&2
echo "[repo-safety]   py -3 -m ai_repo_safety gate --when $WHEN --target ." >&2
echo "[repo-safety]   python -m ai_repo_safety gate --when $WHEN --target ." >&2
echo "[repo-safety]   uvx ai-repo-safety gate --when $WHEN --target ." >&2
exit 1"""
        ran_init = ""
        skip_if_ran = ""

    return f"""#!/usr/bin/env sh
# >>> {marker} >>>
# Git for Windows runs this POSIX script; it does not run a sibling *.cmd.
WHEN={when}
{ran_init}try_mod() {{
  if [ "$#" -lt 1 ]; then
    return 127
  fi
{skip_if_ran}  if ! "$@" -c "import ai_repo_safety.gate" >/dev/null 2>&1; then
    return 127
  fi
{try_body}
}}
if command -v py >/dev/null 2>&1; then
  try_mod py -3 || true
fi
if command -v python3 >/dev/null 2>&1; then
  try_mod python3 || true
fi
if command -v python >/dev/null 2>&1; then
  try_mod python || true
fi
if [ -x ".venv/Scripts/python.exe" ]; then
  try_mod .venv/Scripts/python.exe || true
fi
if [ -x ".venv/bin/python" ]; then
  try_mod .venv/bin/python || true
fi
{tail}
# <<< {marker} <<<
"""


PRE_COMMIT_POSIX = _posix_gate_hook("commit", PRE_COMMIT_MARKER)
PRE_PUSH_POSIX = _posix_gate_hook("auto", PRE_PUSH_MARKER)


def _has_marker(text: str, marker: str) -> bool:
    return marker in text


def _is_only_shebang(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#!"):
            continue
        return False
    return True


def _strip_managed_block(text: str, marker: str) -> str:
    """Remove a previously-installed managed block, leaving any
    user-authored content around it intact."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_block = False
    for line in lines:
        if ">>> " + marker + " >>>" in line:
            in_block = True
            continue
        if "<<< " + marker + " <<<" in line:
            in_block = False
            continue
        if not in_block:
            out.append(line)
    return "".join(out).rstrip() + "\n"


def _chmod_executable(path: Path) -> None:
    current = path.stat().st_mode
    path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _plan_hook(
    path: Path,
    when: str,
    marker: str,
    *,
    overwrite: bool,
    chain: bool,
) -> tuple[str, str] | int:
    """Return ``(action, text_to_write)`` or a numeric refusal code.

    Chained / leftover user content is placed *after* our block. Our
    block then uses fallthrough mode so an existing ``exec`` (pre-commit
    framework) cannot skip the gate.
    """
    standalone = _posix_gate_hook(when, marker, fallthrough=False)
    chained = _posix_gate_hook(when, marker, fallthrough=True)
    if not path.exists():
        return "install", standalone
    existing = path.read_text(encoding="utf-8", errors="replace")
    if _has_marker(existing, marker):
        leftover = _strip_managed_block(existing, marker).strip()
        if leftover and not _is_only_shebang(leftover):
            return "update", chained.rstrip() + "\n\n" + leftover + "\n"
        return "update", standalone
    if not overwrite and not chain:
        print(
            f"[repo-safety] refusing to overwrite existing unmanaged hook: {path}\n"
            f"  Re-run with --chain to keep the existing hook and run it after\n"
            f"  the managed gate, or with --overwrite to replace it."
        )
        return 4
    if chain:
        return "chain", chained.rstrip() + "\n\n" + existing.lstrip()
    return "overwrite", standalone


def install_hooks(
    target: str | Path,
    *,
    overwrite: bool = False,
    chain: bool = False,
    hooks_path: str | None = None,
) -> int:
    """Install native git pre-commit and pre-push hooks.

    Default behavior is safe: refuse to overwrite a pre-existing
    unmanaged hook (exit 4). The caller can opt in to chaining
    (append a managed block after the existing content) or
    overwriting (replace the file with the managed hook).
    """
    root = project_root(target)
    if hooks_path:
        hooks_dir = root / hooks_path
    else:
        git_dir = root / ".git"
        if not git_dir.exists():
            print("[repo-safety] .git directory not found. Initialize Git first: git init")
            return 2
        hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    planned: list[tuple[Path, str, str]] = []
    for path, when, marker in (
        (hooks_dir / "pre-commit", "commit", PRE_COMMIT_MARKER),
        (hooks_dir / "pre-push", "auto", PRE_PUSH_MARKER),
    ):
        result = _plan_hook(path, when, marker, overwrite=overwrite, chain=chain)
        if isinstance(result, int):
            return result
        action, text = result
        planned.append((path, action, text))

    for path, action, text in planned:
        if action == "install":
            write_text(path, text, overwrite=True)
            print(f"[repo-safety] installed {path}")
        elif action == "update":
            path.write_text(text, encoding="utf-8")
            print(f"[repo-safety] updated managed block in {path}")
        elif action == "chain":
            path.write_text(text, encoding="utf-8")
            print(f"[repo-safety] chained managed block before {path}")
        else:
            write_text(path, text, overwrite=True)
            print(f"[repo-safety] installed {path}")
        _chmod_executable(path)

    stale_cmd = hooks_dir / "pre-push.cmd"
    if stale_cmd.exists():
        try:
            existing = stale_cmd.read_text(encoding="utf-8", errors="replace")
        except OSError:
            existing = ""
        if PRE_PUSH_MARKER in existing:
            stale_cmd.unlink()
            print(f"[repo-safety] removed unused {stale_cmd} (Git does not run *.cmd hooks)")

    print("[repo-safety] commit/push/tag gates are git hooks (fail-closed). `--no-verify` is a human escape hatch.")
    return 0
