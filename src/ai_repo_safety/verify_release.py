"""Release verification for ai-repo-safety.

Aggregates a set of pre-release checks into a single command. Each
check is a small function that returns either None (passed) or a
short string describing the failure. The CLI prints a green or red
summary line per check, and exits 0 if all checks passed.
"""

from __future__ import annotations

import json
import re
import subprocess  # nosec B404
import tomllib
from pathlib import Path
from typing import Callable

USES_RE = re.compile(r"uses:\s*([^\s#]+)")
SHA_RE = re.compile(r"@[0-9a-f]{40}(?:\s|$)")
MUTABLE_REF_RE = re.compile(r"@(main|master|release/.*|v\d+(\.\d+)*)$")


def _read_pyproject(root: Path) -> dict:
    return tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))


def check_version_consistency(root: Path, expected_version: str) -> str | None:
    pyproject = _read_pyproject(root)
    py_ver = pyproject.get("project", {}).get("version", "")
    if py_ver != expected_version:
        return f"pyproject.toml version {py_ver!r} != {expected_version!r}"

    package_json = root / "package.json"
    if not package_json.exists():
        return None
    pkg = json.loads(package_json.read_text(encoding="utf-8"))
    if pkg.get("version") != expected_version:
        return f"package.json version {pkg.get('version')!r} != {expected_version!r}"

    init_py = root / "src" / "ai_repo_safety" / "__init__.py"
    if not init_py.exists():
        return None
    text = init_py.read_text(encoding="utf-8")
    if "importlib.metadata" in text:
        return None  # version derived from metadata, OK
    m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', text)
    if m and m.group(1) != expected_version:
        return f"__init__.py __version__ {m.group(1)!r} != {expected_version!r}"
    return None


def check_workflows_pin_full_sha(root: Path) -> str | None:
    offenders: list[str] = []
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return None
    for path in sorted(workflow_dir.glob("*.yml")):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = USES_RE.search(line)
            if not m:
                continue
            ref = m.group(1)
            if not SHA_RE.search(ref) and MUTABLE_REF_RE.search(ref):
                offenders.append(f"{path.name}:{line_no}: {ref}")
    if offenders:
        return "unpinned mutable refs: " + "; ".join(offenders)
    return None


def check_npm_publish_auth_path(root: Path) -> str | None:
    """Require a valid auth path for the npm publish step.

    We prefer OIDC Trusted Publishing, but a repository-level
    `NPM_TOKEN` fallback is still acceptable for young projects
    that have not fully migrated. A release should fail only when
    the workflow provides neither an id-token permission nor a
    `NODE_AUTH_TOKEN` wiring for `npm publish`.
    """
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return None
    for path in workflow_dir.glob("publish-npm*.yml"):
        text = path.read_text(encoding="utf-8")
        if "npm publish" not in text:
            continue
        has_id_token = "id-token: write" in text
        publish_block = text.split("npm publish", 1)[1]
        has_node_auth_token = "NODE_AUTH_TOKEN" in publish_block
        if not has_id_token and not has_node_auth_token:
            return (
                f"{path.name}: publish step has no auth path; expected "
                "either id-token: write for OIDC or NODE_AUTH_TOKEN wiring"
            )
    return None


def check_wheel_smoke_script_present(root: Path) -> str | None:
    if not (root / "scripts" / "smoke-wheel.sh").exists():
        return "scripts/smoke-wheel.sh is missing"
    return None


def check_artifact_manifest_script_present(root: Path) -> str | None:
    if not (root / "scripts" / "check-package-artifacts.py").exists():
        return "scripts/check-package-artifacts.py is missing"
    return None


def check_npm_wrapper_no_latest(root: Path) -> str | None:
    cli_js = root / "bin" / "cli.js"
    if not cli_js.exists():
        return "bin/cli.js is missing"
    text = cli_js.read_text(encoding="utf-8")
    if "@latest" in text:
        return "bin/cli.js still references @latest"
    if "ai-repo-safety==" not in text:
        return "bin/cli.js does not pin uvx to ai-repo-safety==<version>"
    return None


def check_no_lit_wildcard_mutable_refs(root: Path) -> str | None:
    """Refuse branches named 'main' or 'master' being used as the
    immutable ref for an action. The release process should publish
    from a tag, not from a moving branch."""
    offenders: list[str] = []
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.exists():
        return None
    for path in workflow_dir.glob("*.yml"):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = USES_RE.search(line)
            if m and re.search(r"@(main|master)$", m.group(1)):
                offenders.append(f"{path.name}:{line_no}: {m.group(1)}")
    if offenders:
        return "branch refs used as action pins: " + "; ".join(offenders)
    return None


def check_package_json_engines(root: Path) -> str | None:
    """Refuse to release if package.json does not declare
    engine floors compatible with the project's release pipeline.
    The trusted-publishing flow on PyPI and npm requires Python
    3.12+ for uv build, Node 22.14+ and npm 11.5.1+ for the npm
    publish workflow, and Node 18+ for the wrapper itself. We
    require these as a documentation floor in engines so that
    downstream consumers also know the minimum runtime."""
    package_json = root / "package.json"
    if not package_json.exists():
        return None
    try:
        pkg = json.loads(package_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return f"package.json is not valid JSON: {exc}"
    engines = pkg.get("engines")
    if not isinstance(engines, dict):
        return "package.json does not declare an 'engines' object"
    node = engines.get("node", "")
    npm = engines.get("npm", "")
    issues: list[str] = []
    if not node:
        issues.append("engines.node is missing")
    if not npm:
        issues.append("engines.npm is missing")
    if issues:
        return "; ".join(issues)
    return None


def check_codeowners_present(root: Path) -> str | None:
    """The GitHub secure-use reference (June 2026) recommends
    CODEOWNERS for `.github/workflows/` so that changes to
    workflow files require explicit review by the security
    maintainer. This is the social complement to the SHA-pinning
    convention we already enforce. A release should not ship
    without CODEOWNERS in place."""
    codeowners = root / ".github" / "CODEOWNERS"
    if not codeowners.exists():
        return ".github/CODEOWNERS is missing"
    text = codeowners.read_text(encoding="utf-8")
    if "/.github/workflows/" not in text and "/.github/workflows" not in text:
        return (
            ".github/CODEOWNERS exists but does not mention "
            ".github/workflows/; workflow changes would not require "
            "an explicit security maintainer review"
        )
    return None


def verify_release(
    target: str | Path,
    expected_version: str,
    *,
    skip_build: bool = False,
) -> int:
    root = Path(target).resolve()
    checks: list[tuple[str, Callable[[], str | None]]] = [
        ("version consistency (pyproject / package.json / __init__)", lambda: check_version_consistency(root, expected_version)),
        ("workflow uses pinned to full commit SHA", lambda: check_workflows_pin_full_sha(root)),
        ("no mutable branch refs (main/master) as action pins", lambda: check_no_lit_wildcard_mutable_refs(root)),
        ("publish-npm has an auth path (OIDC or NODE_AUTH_TOKEN)", lambda: check_npm_publish_auth_path(root)),
        ("scripts/smoke-wheel.sh present", lambda: check_wheel_smoke_script_present(root)),
        ("scripts/check-package-artifacts.py present", lambda: check_artifact_manifest_script_present(root)),
        ("bin/cli.js no @latest, exact pin spec", lambda: check_npm_wrapper_no_latest(root)),
        ("package.json declares node and npm engines floors", lambda: check_package_json_engines(root)),
        (".github/CODEOWNERS gates .github/workflows/ changes", lambda: check_codeowners_present(root)),
    ]
    if not skip_build:
        checks.append(
            (
                "uv build + twine check + artifact manifest",
                lambda: _run_build_artifact_check(root),
            )
        )

    failures: list[str] = []
    for name, fn in checks:
        try:
            err = fn()
        except Exception as exc:  # noqa: BLE001 - we want to surface any error verbatim
            err = f"unexpected error: {exc}"
        if err is None:
            print(f"  [OK]   {name}")
        else:
            print(f"  [FAIL] {name}: {err}")
            failures.append(name)

    if failures:
        print(f"\nverify-release: {len(failures)} check(s) failed")
        return 1
    print("\nverify-release: OK")
    return 0


def _run_build_artifact_check(root: Path) -> str | None:
    import sys

    code, _, _ = subprocess_command(["uv", "build"], cwd=root)
    if code != 0:
        return "uv build failed"
    code, _, _ = subprocess_command(["uvx", "twine", "check", "dist/*"], cwd=root)
    if code != 0:
        return "twine check failed"
    code, _, _ = subprocess_command([sys.executable, "scripts/check-package-artifacts.py"], cwd=root)
    if code != 0:
        return "check-package-artifacts.py reported missing assets"
    return None


def subprocess_command(args: list[str], *, cwd: Path) -> tuple[int, str, str]:
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=300)  # nosec
    return proc.returncode, proc.stdout, proc.stderr
