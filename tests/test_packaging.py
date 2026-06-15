from __future__ import annotations

from importlib.resources import files
from pathlib import Path

# These assets are read at runtime by `init`, `setup`, `incident`,
# `threat-model`, and `install-hooks` via importlib.resources. If any
# of them is missing from the installed package, those commands
# raise FileNotFoundError. Asserting their presence here is the
# source-tree counterpart of the installed-wheel smoke test
# (`scripts/smoke-wheel.sh`).
REQUIRED_ASSETS: tuple[str, ...] = (
    "templates/universal/AGENTS.md",
    "templates/universal/SECURITY.md",
    "templates/universal/env.example",
    "templates/universal/gitignore.block",
    "templates/universal/dockerignore",
    "templates/universal/pre-commit-config.yaml",
    "templates/python/bandit.yaml",
    "templates/python/pyproject.ai-repo-safety.toml",
    "templates/python/settings.py",
    "templates/python/test_security_basics.py",
    "rules/opengrep/python-dangerous-code.yml",
    "rules/opengrep/github-actions-security.yml",
    "scripts/forbid_sensitive_files.py",
    "scripts/prepush.py",
    "scripts/scan_mcp_config.py",
)


def test_required_assets_are_available_from_package_resources() -> None:
    root = files("ai_repo_safety") / "assets"
    missing: list[str] = []
    for rel in REQUIRED_ASSETS:
        if not (root / rel).is_file():
            missing.append(rel)
    assert not missing, f"missing required package assets: {missing}"


def test_npm_wrapper_does_not_use_unpinned_latest() -> None:
    text = Path("bin/cli.js").read_text(encoding="utf-8")
    assert "@latest" not in text, (
        "bin/cli.js must not reference @latest; the npm wrapper must pin the "
        "PyPI version it delegates to."
    )
    assert "ai-repo-safety==" in text, (
        "bin/cli.js must pin the uvx resolution to ai-repo-safety==<version>."
    )


def test_npm_and_python_versions_match() -> None:
    import json

    import tomllib

    package = json.loads(Path("package.json").read_text(encoding="utf-8"))
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert package["version"] == pyproject["project"]["version"], (
        f"package.json version {package['version']} does not match pyproject "
        f"{pyproject['project']['version']}"
    )


def test_source_tree_version_falls_back_safely() -> None:
    # Without a built/installed distribution, importlib.metadata raises
    # PackageNotFoundError. The package must surface a clearly non-semver
    # placeholder instead of pretending to be a real release.
    import ai_repo_safety

    import tomllib

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    declared = pyproject["project"]["version"]
    # Either the installed metadata is reachable (version == declared)
    # or the explicit local fallback is in effect.
    assert ai_repo_safety.__version__ in {declared, "0.0.0+local"}
