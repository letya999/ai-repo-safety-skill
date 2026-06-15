"""Integration test for the verify-release exit code contract.

The individual checks in `verify_release.py` are unit-tested
elsewhere. This file exercises the full `verify_release(...)`
function on a clean tree (expects 0) and on a deliberately
broken tree (expects 1). It exists so that a regression in
the orchestrator (e.g. someone short-circuits all checks, or
swaps the 0/1 mapping) is caught at integration time, not at
release time.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from ai_repo_safety.verify_release import verify_release


def test_verify_release_returns_zero_on_clean_tree() -> None:
    code = verify_release(Path("."), "0.1.3", skip_build=True)
    assert code == 0, f"verify-release should return 0 on a clean tree, got {code}"


def test_verify_release_returns_one_when_codeowners_is_missing(tmp_path: Path) -> None:
    """A broken tree where .github/CODEOWNERS is missing should
    cause verify-release to return 1 (one or more checks failed)."""
    # The orchestrator walks a stable set of checks; with a brand-new
    # empty tmp_path, several checks will report failures. We only
    # assert the exit code, not which individual check failed, so
    # that adding new checks to verify_release in the future does
    # not break this contract test.
    code = verify_release(tmp_path, "0.1.3", skip_build=True)
    assert code == 1, f"verify-release should return 1 on a broken tree, got {code}"


def test_verify_release_skip_build_actually_skips_uv_build(tmp_path: Path) -> None:
    """The skip_build=True flag must prevent any uv build or
    twine check from running. The simplest way to assert that is
    to point the target at a tmp_path and confirm that no
    `dist/` subdirectory is created."""
    code = verify_release(tmp_path, "0.1.3", skip_build=True)
    assert not (tmp_path / "dist").exists(), (
        "verify-release(skip_build=True) still created a dist/ directory"
    )
    assert code == 1, f"expected 1 (broken tree), got {code}"


def test_installed_wheel_contains_all_required_assets() -> None:
    """Final integration check: every asset that the runtime CLI
    needs must be present in the most recently built wheel. This
    is the test that would have caught the 0.1.3 release-blocker
    (D0) at CI time. The build must be re-run by the caller; we
    only consume the dist/ directory if it exists."""
    dist = Path("dist")
    if not dist.exists():
        pytest.skip("dist/ not present; run `uv build` first")
    whl = next(dist.glob("*.whl"), None)
    if whl is None:
        pytest.skip("no wheel in dist/")
    required = {
        "ai_repo_safety/assets/templates/universal/AGENTS.md",
        "ai_repo_safety/assets/templates/universal/SECURITY.md",
        "ai_repo_safety/assets/templates/python/bandit.yaml",
        "ai_repo_safety/assets/templates/python/pyproject.ai-repo-safety.toml",
        "ai_repo_safety/assets/rules/opengrep/python-dangerous-code.yml",
        "ai_repo_safety/assets/scripts/forbid_sensitive_files.py",
        "ai_repo_safety/assets/scripts/prepush.py",
        "ai_repo_safety/assets/scripts/scan_mcp_config.py",
    }
    names = set(zipfile.ZipFile(whl).namelist())
    missing = sorted(required - names)
    assert not missing, f"missing assets in built wheel: {missing}"
