from __future__ import annotations

from pathlib import Path

from ai_repo_safety.fast_scan import (
    ALLOWLIST_PRAGMA_RE,
    FORBIDDEN_PATTERNS,
    scan_directory,
)


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_scan_allows_env_example(tmp_path: Path) -> None:
    _write(tmp_path / "env.example", "API_KEY=replace_me\n")
    _write(tmp_path / ".env.example", "DATABASE_URL=postgresql://example\n")
    findings = scan_directory(tmp_path)
    assert all(f.get("file") not in {"env.example", ".env.example"} for f in findings), (
        f"env example templates must not be reported as forbidden: {findings}"
    )


def test_scan_flags_real_env(tmp_path: Path) -> None:
    _write(tmp_path / ".env", "API_KEY=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n")
    findings = scan_directory(tmp_path)
    forbidden = [f for f in findings if f.get("type") == "forbidden_file"]
    assert any(f.get("file") == ".env" for f in forbidden), (
        f"real .env must be reported as forbidden: {findings}"
    )


def test_scan_classifies_template_private_key_placeholder(tmp_path: Path) -> None:
    _write(
        tmp_path / "src/app/templates/example.py",
        "-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----\n",
    )
    findings = scan_directory(tmp_path)
    secret_findings = [f for f in findings if f.get("type") in {"secret_content", "secret_placeholder"}]
    assert secret_findings, "expected a secret finding in templates"
    # Inside /templates/ we expect the placeholder classification, not a
    # high-confidence "secret_content" alert.
    assert all(f.get("type") == "secret_placeholder" for f in secret_findings), (
        f"template fixture should be classified as placeholder: {secret_findings}"
    )


def test_scan_does_not_echo_secret_values(tmp_path: Path) -> None:
    _write(
        tmp_path / "leak.txt",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD\n",
    )
    findings = scan_directory(tmp_path)
    secret = [f for f in findings if "Personal Access Token" in f.get("message", "")]
    assert secret, "expected secret finding for live PAT"
    serialized = "\n".join(repr(f) for f in secret)
    assert "abcdefghijklmnopqrstuvwxyz" not in serialized, (
        "fast_scan must not echo the matched secret value in findings"
    )


def test_scan_honors_allowlist_pragma(tmp_path: Path) -> None:
    _write(
        tmp_path / "fixture.py",
        "# pragma: allowlist secret\nAPI_KEY = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD'\n",
    )
    findings = scan_directory(tmp_path)
    assert not findings, (
        f"pragma: allowlist secret should suppress findings, got: {findings}"
    )


def test_forbidden_patterns_cover_critical_files() -> None:
    for needle in (".env", "*.pem", "*.key", ".mcp.json", "id_rsa", "secrets.json"):
        assert needle in FORBIDDEN_PATTERNS, (
            f"{needle} must remain in FORBIDDEN_PATTERNS to keep the "
            f"package's denylist effective"
        )


def test_allowlist_pragma_regex_matches_python_and_js_comments() -> None:
    assert ALLOWLIST_PRAGMA_RE.search("# pragma: allowlist secret")
    assert ALLOWLIST_PRAGMA_RE.search("// pragma: allowlist secret")
    assert ALLOWLIST_PRAGMA_RE.search("# pragma: allowlist SECRET")  # case insensitive
    assert not ALLOWLIST_PRAGMA_RE.search("plain text without pragma")
