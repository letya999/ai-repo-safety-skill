from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import subprocess  # nosec
import sys
from importlib import resources
from pathlib import Path
from typing import Mapping, Sequence

PACKAGE = "ai_repo_safety"
_logger = logging.getLogger("ai_repo_safety.util")
_env_prepared = False


def _extra_path_dirs() -> list[str]:
    """Return the candidate PATH additions for the CLI environment.

    Pure function; no I/O until the caller actually asks for the
    PATH augmentation via :func:`prepare_cli_environment`. Importing
    :mod:`ai_repo_safety.util` no longer mutates ``os.environ``.
    """
    extras: list[str] = []
    # Virtual environment's bin/Scripts directory, so subprocesses can
    # find tools installed into the active venv.
    extras.append(str(Path(sys.executable).parent))
    # Always ensure the user-local bin is present.
    extras.append(str(Path.home() / ".local" / "bin"))
    # Opengrep default install path.
    extras.append(str(Path.home() / ".opengrep" / "cli" / "latest"))

    if platform.system().lower() == "windows":
        # On Windows, dynamically read the latest PATH from the registry
        # to capture freshly added winget / scoop / npm-global paths.
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                val, _ = winreg.QueryValueEx(key, "PATH")
            if val:
                val_expanded = os.path.expandvars(val)
                for p in val_expanded.split(";"):
                    p = p.strip()
                    if p and p != "$($env:PATH)":
                        extras.append(p)
        except Exception as exc:  # nosec B110
            # The host may not be Windows, or the registry key may be
            # missing; both cases are non-fatal. Log at debug so
            # diagnostics are available without spamming the user.
            _logger.debug("windows registry PATH lookup skipped: %s", exc)
    return extras


def prepare_cli_environment() -> None:
    """Normalize the PATH for the CLI entry point.

    Idempotent. Call this once from the CLI main() before any
    subprocess-based command runs. Importing this module no longer
    triggers PATH mutation as a side effect.
    """
    global _env_prepared
    if _env_prepared:
        return

    current = os.environ.get("PATH", "").split(os.pathsep)
    seen: set[str] = set()
    final: list[str] = []
    for p in _extra_path_dirs() + current:
        norm = os.path.abspath(p).lower() if os.path.isabs(p) else p.lower()
        if norm in seen:
            continue
        seen.add(norm)
        final.append(p)
    os.environ["PATH"] = os.pathsep.join(final)
    _env_prepared = True


def norm_path(path: str | Path) -> str:
    return str(path).replace("\\", "/")


def project_root(path: str | Path | None = None) -> Path:
    return Path(path or ".").resolve()


def asset_text(relative_path: str) -> str:
    return (resources.files(PACKAGE) / "assets" / relative_path).read_text(encoding="utf-8")


def asset_bytes(relative_path: str) -> bytes:
    return (resources.files(PACKAGE) / "assets" / relative_path).read_bytes()


def write_text(path: Path, content: str, *, overwrite: bool = False) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        return False
    path.write_text(content, encoding="utf-8")
    return True


def append_marked_block(path: Path, marker: str, block: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    begin = f"# >>> {marker} >>>"
    end = f"# <<< {marker} <<<"
    new_block = f"\n{begin}\n{block.rstrip()}\n{end}\n"
    if not path.exists():
        path.write_text(new_block.lstrip(), encoding="utf-8")
        return "created"
    text = path.read_text(encoding="utf-8", errors="replace")
    pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), flags=re.S)
    if pattern.search(text):
        text = pattern.sub(new_block.strip(), text)
        path.write_text(text.rstrip() + "\n", encoding="utf-8")
        return "updated"
    path.write_text(text.rstrip() + new_block, encoding="utf-8")
    return "appended"


def run_cmd(
    args: Sequence[str],
    cwd: Path | None = None,
    timeout: int = 120,
    env: Mapping[str, str] | None = None,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(  # nosec
            list(args),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            env=dict(env) if env is not None else None,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        # TimeoutExpired.stdout/stderr may be bytes or str; we
        # always decode to str to keep the return type stable.
        def _decode(value: object) -> str:
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            if isinstance(value, str):
                return value
            return ""

        return (
            124,
            _decode(getattr(exc, "stdout", b"")),
            _decode(getattr(exc, "stderr", b"")) or f"Timeout after {timeout}s",
        )


def which(name: str) -> str | None:
    return shutil.which(name)


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def current_platform() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def in_git_repo(root: Path) -> bool:
    code, _, _ = run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=root)
    return code == 0


def git_has_commits(root: Path) -> bool:
    code, _, _ = run_cmd(["git", "rev-parse", "HEAD"], cwd=root)
    return code == 0


def git_origin(root: Path) -> str | None:
    code, out, _ = run_cmd(["git", "remote", "get-url", "origin"], cwd=root)
    if code == 0:
        return out.strip()
    return None


def parse_github_repo_from_url(url: str | None) -> str | None:
    if not url:
        return None
    # Owner and repo may contain letters, digits, hyphens, underscores,
    # and dots (GitHub allows them in repo names, just not at the end).
    patterns = [
        r"github\.com[:/](?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?$",
        r"https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?$",
    ]
    for pat in patterns:
        m = re.search(pat, url)
        if m:
            return f"{m.group('owner')}/{m.group('repo')}"
    return None


def detect_python_project(root: Path) -> bool:
    if (root / "pyproject.toml").exists() or (root / "requirements.txt").exists():
        return True
    return any(root.glob("**/*.py"))


def detect_github_project(root: Path) -> bool:
    if (root / ".github").exists():
        return True
    return bool(parse_github_repo_from_url(git_origin(root)))


def parse_gitlab_repo_from_url(url: str | None, gitlab_host: str = "gitlab.com") -> str | None:
    """Extract the namespace/project path from a GitLab remote URL.

    Handles both HTTPS and SSH remote formats:
      https://gitlab.com/ns/project.git  -> ns/project
      git@gitlab.com:ns/sub/project.git  -> ns/sub/project
      https://internal.corp/ns/project   -> ns/project  (when gitlab_host set)
      git@internal.corp:ns/project.git   -> ns/project  (when gitlab_host set)
    """
    if not url:
        return None
    host_escaped = re.escape(gitlab_host)
    # SSH: git@host:path/to/repo(.git)?
    ssh_pat = rf"^git@{host_escaped}:(?P<repo_path>[A-Za-z0-9_./-]+?)(?:\.git)?$"
    # HTTPS: https?://host/path/to/repo(.git)?
    https_pat = rf"https?://{host_escaped}/(?P<repo_path>[A-Za-z0-9_./-]+?)(?:\.git)?$"
    for pat in (ssh_pat, https_pat):
        m = re.search(pat, url.strip())
        if m:
            return m.group("repo_path").strip("/")
    return None


def detect_gitlab_project(root: Path) -> bool:
    if (root / ".gitlab-ci.yml").exists() or (root / ".gitlab").exists():
        return True
    return bool(parse_gitlab_repo_from_url(git_origin(root)))


def load_json(path: Path, default: dict | None = None) -> dict:
    if not path.exists():
        return default or {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default or {}


def dump_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def print_table(rows: list[tuple[str, str, str]]) -> None:
    if not rows:
        return
    widths = [max(len(str(r[i])) for r in rows) for i in range(3)]
    for a, b, c in rows:
        print(f"{a:<{widths[0]}}  {b:<{widths[1]}}  {c}")


__all__ = [
    "PACKAGE",
    "norm_path",
    "project_root",
    "asset_text",
    "asset_bytes",
    "write_text",
    "append_marked_block",
    "run_cmd",
    "which",
    "is_windows",
    "current_platform",
    "in_git_repo",
    "git_has_commits",
    "git_origin",
    "parse_github_repo_from_url",
    "parse_gitlab_repo_from_url",
    "detect_python_project",
    "detect_github_project",
    "detect_gitlab_project",
    "load_json",
    "dump_json",
    "print_table",
    "prepare_cli_environment",
]
