from __future__ import annotations

from pathlib import Path

from ai_repo_safety.verify_release import (
    check_artifact_manifest_script_present,
    check_npm_wrapper_no_latest,
    check_no_lit_wildcard_mutable_refs,
    check_no_npm_token_publish_path,
    check_version_consistency,
    check_wheel_smoke_script_present,
    check_workflows_pin_full_sha,
)


def test_version_consistency_passes_for_current_tree() -> None:
    assert check_version_consistency(Path("."), "0.1.3") is None


def test_version_consistency_fails_on_mismatch(tmp_path: Path) -> None:
    import json

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "ai-repo-safety"\nversion = "0.0.1"\n', encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "ai-repo-safety", "version": "0.0.1"}), encoding="utf-8"
    )
    err = check_version_consistency(tmp_path, "0.1.4")
    assert err is not None
    assert "0.0.1" in err and "0.1.4" in err


def test_workflows_pin_full_sha_passes() -> None:
    assert check_workflows_pin_full_sha(Path(".")) is None


def test_workflows_pin_full_sha_fails(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: push\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    err = check_workflows_pin_full_sha(tmp_path)
    assert err is not None
    assert "unpinned" in err


def test_no_lit_wildcard_mutable_refs_fails_on_branch_pin(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: push\njobs:\n  x:\n    steps:\n      - uses: trufflesecurity/trufflehog@main\n",
        encoding="utf-8",
    )
    err = check_no_lit_wildcard_mutable_refs(tmp_path)
    assert err is not None
    assert "trufflehog@main" in err


def test_npm_wrapper_passes() -> None:
    assert check_npm_wrapper_no_latest(Path(".")) is None


def test_npm_wrapper_fails_on_latest(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir(parents=True)
    (tmp_path / "bin" / "cli.js").write_text(
        "const { spawn } = require('child_process'); spawn('uvx', ['ai-repo-safety@latest']);",
        encoding="utf-8",
    )
    err = check_npm_wrapper_no_latest(tmp_path)
    assert err is not None
    assert "@latest" in err


def test_smoke_script_present() -> None:
    assert check_wheel_smoke_script_present(Path(".")) is None


def test_artifact_manifest_script_present() -> None:
    assert check_artifact_manifest_script_present(Path(".")) is None


def test_no_npm_token_publish_path_passes() -> None:
    assert check_no_npm_token_publish_path(Path(".")) is None


def test_no_npm_token_publish_path_flags_secret_read(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "publish-npm.yml").write_text(
        "name: publish-npm\n"
        "jobs:\n"
        "  publish:\n"
        "    steps:\n"
        "      - name: publish\n"
        "        run: npm publish --access public\n"
        "        env:\n"
        "          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n",
        encoding="utf-8",
    )
    err = check_no_npm_token_publish_path(tmp_path)
    assert err is not None
    assert "NODE_AUTH_TOKEN" in err
