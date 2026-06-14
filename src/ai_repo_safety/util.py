from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from importlib import resources

PACKAGE = "ai_repo_safety"


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


def run_cmd(args: Sequence[str], cwd: Path | None = None, timeout: int = 120) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", exc.stderr or f"Timeout after {timeout}s"


def which(name: str) -> str | None:
    return shutil.which(name)


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def current_platform() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def in_git_repo(root: Path) -> bool:
    code, _, _ = run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=root)
    return code == 0


def git_origin(root: Path) -> str | None:
    code, out, _ = run_cmd(["git", "remote", "get-url", "origin"], cwd=root)
    if code == 0:
        return out.strip()
    return None


def parse_github_repo_from_url(url: str | None) -> str | None:
    if not url:
        return None
    patterns = [
        r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$",
        r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$",
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
