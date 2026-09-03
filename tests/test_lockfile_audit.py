from __future__ import annotations

from pathlib import Path

from ai_repo_safety.lockfile_audit import audit_lockfile


def test_lockfile_audit_uses_osv_not_pip_api(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    seen_env: dict[str, str] = {}

    def fake_which(name: str) -> str | None:
        return name if name == "osv-scanner" else None

    def fake_run(args, cwd=None, timeout=120, env=None):
        if env and "PIPAPI_PYTHON_LOCATION" in env:
            seen_env["PIPAPI_PYTHON_LOCATION"] = env["PIPAPI_PYTHON_LOCATION"]
        if args and args[0] == "osv-scanner":
            assert "--lockfile" in args
            return 0, "", ""
        return 0, "", ""

    monkeypatch.setattr("ai_repo_safety.lockfile_audit.which", fake_which)
    monkeypatch.setattr("ai_repo_safety.lockfile_audit.run_cmd", fake_run)
    code, detail = audit_lockfile(tmp_path, required=True)
    assert code == 0
    assert "osv-scanner" in detail
    assert "PIPAPI_PYTHON_LOCATION" not in seen_env


def test_no_lockfile_fails_only_when_required(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    code, _ = audit_lockfile(tmp_path, required=False)
    assert code == 0
    code, detail = audit_lockfile(tmp_path, required=True)
    assert code == 2
    assert "no uv.lock" in detail


def test_commit_gate_does_not_audit_lockfile(tmp_path: Path, monkeypatch) -> None:
    called: list[int] = []
    monkeypatch.setattr(
        "ai_repo_safety.lockfile_audit.audit_lockfile",
        lambda *a, **k: called.append(1) or (0, ""),
    )
    monkeypatch.setattr("ai_repo_safety.gate.which", lambda name: "gitleaks" if name == "gitleaks" else None)
    monkeypatch.setattr(
        "ai_repo_safety.gate.run_cmd",
        lambda args, cwd=None, timeout=120, env=None: (0, "", ""),
    )
    monkeypatch.setattr(
        "ai_repo_safety.gate._run_packaged_or_helper",
        lambda *a, **k: (0, "", ""),
    )
    from ai_repo_safety.gate import run_gate

    assert run_gate(tmp_path, when="commit") == 0
    assert called == []
