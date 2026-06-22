from __future__ import annotations

from importlib.resources import files
from pathlib import Path
import sys
import pytest

# These assets are read at runtime by `init`, `setup`, `incident`,
# `threat-model`, and `install-hooks` via importlib.resources. If any
# of them is missing from the installed package, those commands
# raise FileNotFoundError. Asserting their presence here is the
# source-tree counterpart of the installed-wheel smoke test
# (`scripts/smoke-wheel.sh`).
REQUIRED_ASSETS: tuple[str, ...] = (
    "docs/agent-hooks.md",
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
    "scripts/agent_hook_runner.py",
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


def test_package_json_declares_runtime_engines() -> None:
    """Per the June 2026 npm Trusted Publishing reference, the
    wrapper must declare the runtime floors it supports so that
    downstream consumers know the minimum Node and npm versions.
    We require both `engines.node` and `engines.npm` to be
    present and non-empty. The `>=18` floor for node matches the
    `bin/cli.js` runtime (which only uses `node:child_process`,
    `node:fs`, and `path`).
    """
    import json

    package = json.loads(Path("package.json").read_text(encoding="utf-8"))
    engines = package.get("engines")
    assert isinstance(engines, dict), "package.json must declare an 'engines' object"
    assert engines.get("node"), "engines.node must be a non-empty string"
    assert engines.get("npm"), "engines.npm must be a non-empty string"


def test_index_js_is_a_valid_noop_proxy() -> None:
    """`package.json.main` is `index.js`. The file must be a
    valid CommonJS module that does not throw on `require` and
    exposes an empty object (a documented no-op proxy: the CLI is
    in Python, not Node)."""
    import json
    import subprocess  # nosec

    package = json.loads(Path("package.json").read_text(encoding="utf-8"))
    assert package.get("main") == "index.js", (
        f"package.json.main is {package.get('main')!r}; expected 'index.js'"
    )
    assert Path("index.js").exists(), "index.js is missing despite being listed as main"
    # Simpler: just verify the file is loadable as CommonJS via node.
    node_test = subprocess.run(  # nosec
        ["node", "-e",
         "const m = require('./index.js'); "
         "if (typeof m !== 'object' || m === null) process.exit(1); "
         "if (Array.isArray(m)) process.exit(2); "
         "if (Object.keys(m).length !== 0) process.exit(3);"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert node_test.returncode == 0, (
        f"index.js proxy check failed: {node_test.returncode}\n"
        f"stdout: {node_test.stdout}\n"
        f"stderr: {node_test.stderr}"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="chmod/stat.S_IXUSR is not available on Windows")
def test_package_json_bin_field_points_to_existing_file() -> None:
    """The `bin` field maps the command name to a relative path
    under the package root. The file must exist and be marked
    executable so that `npm install -g` creates a working shim.
    """
    import json
    import stat

    package = json.loads(Path("package.json").read_text(encoding="utf-8"))
    bin_field = package.get("bin")
    assert isinstance(bin_field, dict), "package.json must declare a 'bin' object"
    for cmd, rel_path in bin_field.items():
        full = Path(rel_path)
        assert full.exists(), f"bin entry {cmd!r} → {rel_path!r}: file does not exist"
        assert full.is_file(), f"bin entry {cmd!r} → {rel_path!r}: not a regular file"
        mode = full.stat().st_mode
        # The POSIX executable bit is what npm/Unix shims rely on.
        # The bit is not present on Windows; the test is allowed
        # to skip there via xfail; in this project we only test on
        # POSIX CI hosts.
        assert mode & stat.S_IXUSR, (
            f"bin entry {cmd!r} → {rel_path!r}: user-executable bit is not set; "
            "the npm shim will fail with EACCES on install"
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
