from __future__ import annotations

import stat
import subprocess
from pathlib import Path

from ai_repo_safety.cli import main


def _init_repo(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)


def test_install_hooks_fresh_repo(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    code = main(["install-hooks", "--target", str(tmp_path)])
    assert code == 0
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    assert hook.exists()
    # The hook should be executable on POSIX.
    mode = hook.stat().st_mode
    assert mode & stat.S_IXUSR


def test_install_hooks_refuses_unmanaged_existing_hook(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/usr/bin/env sh\necho 'custom user hook'\n", encoding="utf-8")
    hook.chmod(0o755)
    code = main(["install-hooks", "--target", str(tmp_path)])
    assert code == 4, f"expected policy violation (4), got {code}"
    # Existing content is preserved.
    assert "custom user hook" in hook.read_text(encoding="utf-8")


def test_install_hooks_chain_preserves_existing(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/usr/bin/env sh\necho 'custom user hook'\n", encoding="utf-8")
    hook.chmod(0o755)
    code = main(["install-hooks", "--target", str(tmp_path), "--chain"])
    assert code == 0
    text = hook.read_text(encoding="utf-8")
    assert "custom user hook" in text
    assert "AI REPO SAFETY PRE-PUSH" in text


def test_install_hooks_updates_managed_block(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(
        "#!/usr/bin/env sh\n"
        "# >>> AI REPO SAFETY PRE-PUSH >>>\n"
        "echo OLD\n"
        "# <<< AI REPO SAFETY PRE-PUSH <<<\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    code = main(["install-hooks", "--target", str(tmp_path)])
    assert code == 0
    text = hook.read_text(encoding="utf-8")
    assert "echo OLD" not in text
    assert "ai-repo-safety prepush --target" in text


def test_install_hooks_overwrite_requires_flag(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hook = tmp_path / ".git" / "hooks" / "pre-push"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/usr/bin/env sh\necho 'custom user hook'\n", encoding="utf-8")
    hook.chmod(0o755)
    code = main(["install-hooks", "--target", str(tmp_path), "--overwrite"])
    assert code == 0
    text = hook.read_text(encoding="utf-8")
    assert "custom user hook" not in text
    assert "AI REPO SAFETY PRE-PUSH" in text


def test_install_hooks_refuses_when_no_git(tmp_path: Path) -> None:
    code = main(["install-hooks", "--target", str(tmp_path)])
    assert code == 2


def test_install_hooks_supports_custom_hooks_path(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    code = main(
        [
            "install-hooks",
            "--target",
            str(tmp_path),
            "--hooks-path",
            ".githooks",
        ]
    )
    assert code == 0
    custom = tmp_path / ".githooks" / "pre-push"
    assert custom.exists()
    assert "AI REPO SAFETY PRE-PUSH" in custom.read_text(encoding="utf-8")
