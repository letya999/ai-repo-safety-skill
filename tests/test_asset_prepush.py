"""Tests for the helper scripts that ai-repo-safety copies into
target repositories under `scripts/security/`. These are the
files that downstream repos will actually run, so they deserve
direct coverage in addition to the scanner.py tests.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

# assets/scripts/prepush.py is a top-level script (not inside a
# package). We import it by file path to exercise the same code
# path that target repos will execute.
PREPUSH_PATH = Path(__file__).resolve().parent.parent / "src" / "ai_repo_safety" / "assets" / "scripts" / "prepush.py"


def _load_prepush_module() -> Any:
    spec = importlib.util.spec_from_file_location("prepush_under_test", PREPUSH_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_trufflehog_since_commit_returns_valid_sha_on_repo_with_history() -> None:
    """The current repository has a multi-commit history, so the
    helper should return a 40-character SHA. We do not assert a
    specific value because the SHA changes every time the local
    branch moves; we only assert the contract that the helper
    honors."""
    module = _load_prepush_module()
    sha = module.trufflehog_since_commit()
    if sha is None:
        pytest.skip("git history not available in this environment")
    assert isinstance(sha, str)
    assert len(sha) == 40
    assert all(c in "0123456789abcdef" for c in sha)


def test_python_executable_prefers_sys_executable() -> None:
    """The helper script must invoke local security scripts via
    sys.executable rather than the bare `python` alias; otherwise
    host images without a `python` shim break the pre-push gate."""
    import sys as _sys

    module = _load_prepush_module()
    assert module.python_executable() == _sys.executable


def test_git_has_commits_true_in_this_repo() -> None:
    """The fixture is a real Git working copy, so git_has_commits
    must return True."""
    module = _load_prepush_module()
    assert module.git_has_commits() is True
