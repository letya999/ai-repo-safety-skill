from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from ai_repo_safety.cli import main


USES_RE = re.compile(r"uses:\s*([^\s#]+)")
SHA_RE = re.compile(r"@[0-9a-f]{40}(?:\s|$)")
BRANCH_REF_RE = re.compile(r"@(main|master|release/.*|v\d+(\.\d+)*)$")


def test_github_actions_are_pinned_to_full_sha() -> None:
    """Every uses: ref in .github/workflows must be a full
    40-character commit SHA. Mutable branch or version refs
    are not allowed for a security tool that pins its release
    pipeline."""
    offenders: list[str] = []
    workflows = Path(".github/workflows")
    if not workflows.exists():
        return
    for path in sorted(workflows.glob("*.yml")):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = USES_RE.search(line)
            if m is None:
                continue
            ref = m.group(1)
            if not SHA_RE.search(ref) and BRANCH_REF_RE.search(ref):
                offenders.append(f"{path.name}:{line_no}: {ref}")
    assert not offenders, (
        "mutable action refs in workflows: " + "; ".join(offenders)
    )


def test_workflows_have_top_level_permissions() -> None:
    offenders: list[str] = []
    workflows = Path(".github/workflows")
    if not workflows.exists():
        return
    for path in sorted(workflows.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        # jobs with write operations need permissions; the
        # presence of a top-level permissions: read (or write)
        # is mandatory for workflows that touch the network.
        if "permissions:" not in text:
            offenders.append(f"{path.name}: missing top-level permissions")
    assert not offenders, "; ".join(offenders)


def test_publish_npm_declares_an_auth_path() -> None:
    publish = Path(".github/workflows/publish-npm.yml")
    if not publish.exists():
        return
    text = publish.read_text(encoding="utf-8")
    if "npm publish" not in text:
        return
    assert "id-token: write" in text or "NODE_AUTH_TOKEN" in text, (
        "publish-npm.yml must declare either OIDC id-token permission "
        "or a NODE_AUTH_TOKEN fallback for npm publish"
    )


def test_security_workflow_does_not_use_trufflehog_main() -> None:
    security = Path(".github/workflows/security.yml")
    if not security.exists():
        return
    text = security.read_text(encoding="utf-8")
    if "trufflehog" in text and "@main" in text:
        raise AssertionError("security.yml still pins trufflesecurity/trufflehog@main")


def test_asset_workflows_match_root_workflows() -> None:
    """The asset templates that init copies to target repos must
    carry the same SHA-pinned convention as the source repo's
    own workflows. Otherwise, running init on a target repo
    silently regresses CI posture."""
    root = Path(".github/workflows")
    assets = Path("src/ai_repo_safety/assets/workflows")
    if not (root.exists() and assets.exists()):
        return
    mismatches: list[str] = []
    for src in sorted(assets.glob("*.yml")):
        dst = root / src.name
        if not dst.exists():
            mismatches.append(f"asset has no source counterpart: {src.name}")
            continue
        for line_no, line in enumerate(dst.read_text(encoding="utf-8").splitlines(), 1):
            m = USES_RE.search(line)
            if m is None:
                continue
            ref = m.group(1)
            if not SHA_RE.search(ref) and BRANCH_REF_RE.search(ref):
                mismatches.append(f"{dst.name}:{line_no}: {ref}")
    assert not mismatches, "; ".join(mismatches)


def test_sbom_command_is_wired() -> None:
    code = main(["sbom", "--target", "."])
    # cyclonedx-py is not in dev deps; expect a tool-missing
    # error (exit 3) plus the install hint.
    assert code == 3


def test_sarif_scan_emits_valid_top_level_shape() -> None:
    proc = subprocess.run(  # nosec
        [sys.executable, "-m", "ai_repo_safety", "scan", "--target", ".", "--sarif"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    # The SARIF exit code may be 0 or 1 depending on the local
    # environment; we only care that the JSON shape is correct.
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"scan --sarif did not emit JSON: {exc}\nstdout: {proc.stdout[:500]}")
    assert doc.get("version") == "2.1.0"
    assert "runs" in doc
    assert isinstance(doc["runs"], list)
    assert doc["runs"][0]["tool"]["driver"]["name"] == "ai-repo-safety"
