from __future__ import annotations

from pathlib import Path


def test_env_file_is_not_committed() -> None:
    assert not Path(".env").exists() or ".env" in Path(".gitignore").read_text(encoding="utf-8")


def test_env_example_has_placeholders_only() -> None:
    text = Path(".env.example").read_text(encoding="utf-8")
    assert "replace_me" in text
    assert "-----BEGIN PRIVATE KEY-----" not in text
